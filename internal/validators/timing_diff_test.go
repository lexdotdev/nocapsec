package validators_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Timing arms differ only in the injected query value; the clock and handlers
// key off that value (not the path), since the engine builds all arms from one
// base_request.
const (
	timingParam = "id"
	valControl  = "1"
	valLow      = "1 AND SLEEP(0)"
	valHigh     = "1 AND SLEEP(5)"
)

func timingJob(t *testing.T, port int, findingType string) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item?id=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": timingParam},
			"payloads": map[string]string{
				"control":    valControl,
				"delay_low":  valLow,
				"delay_high": valHigh,
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"repetitions":             3,
		"min_median_delta_ms":     3000,
		"require_body_similarity": true,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-timing",
			Type:      findingType,
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
	}
}

func timingEnv(t *testing.T, srv *httptest.Server, clock validators.Clock) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     clock,
	}
}

// valChanClock is a Clock that receives the injected query value from the
// handler, returning a predetermined duration for each arm.
type valChanClock interface {
	validators.Clock
	recordVal(val string)
}

// pathAwareClock returns fixed durations keyed by the injected query value.
type pathAwareClock struct {
	vals    chan string
	control time.Duration
	low     time.Duration
	high    time.Duration
}

func newPathAwareClock(controlMS, lowMS, highMS int) *pathAwareClock {
	return &pathAwareClock{
		vals:    make(chan string, 100),
		control: time.Duration(controlMS) * time.Millisecond,
		low:     time.Duration(lowMS) * time.Millisecond,
		high:    time.Duration(highMS) * time.Millisecond,
	}
}

func (c *pathAwareClock) Now() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func (c *pathAwareClock) Since(_ time.Time) time.Duration {
	switch <-c.vals {
	case valControl:
		return c.control
	case valLow:
		return c.low
	case valHigh:
		return c.high
	default:
		return c.control
	}
}

func (c *pathAwareClock) recordVal(val string) {
	c.vals <- val
}

// pathRecordingHandler sends each request's injected query value to the clock.
func pathRecordingHandler(clock *pathAwareClock) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clock.vals <- r.URL.Query().Get(timingParam)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
	})
}

func pathRecordingHandlerGeneric(clock valChanClock) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clock.recordVal(r.URL.Query().Get(timingParam))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
	})
}

// unstableControlClock cycles through variable control durations.
type unstableControlClock struct {
	vals        chan string
	controlDurs []time.Duration
	controlIdx  int
	low         time.Duration
	high        time.Duration
}

func (c *unstableControlClock) Now() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func (c *unstableControlClock) Since(_ time.Time) time.Duration {
	switch <-c.vals {
	case valControl:
		d := c.controlDurs[c.controlIdx%len(c.controlDurs)]
		c.controlIdx++
		return d
	case valLow:
		return c.low
	case valHigh:
		return c.high
	default:
		return 50 * time.Millisecond
	}
}

func (c *unstableControlClock) recordVal(val string) {
	c.vals <- val
}

func TestSQLiTimingVerified(t *testing.T) {
	clock := newPathAwareClock(50, 1000, 5000)
	srv := httptest.NewServer(pathRecordingHandler(clock))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, ok := validators.Lookup("sqli.time_based")
	if !ok {
		t.Fatal("validator not registered")
	}

	job := timingJob(t, port, "sqli.time_based")
	env := timingEnv(t, srv, clock)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

func TestCommandInjectionTimingVerified(t *testing.T) {
	clock := newPathAwareClock(50, 1000, 5000)
	srv := httptest.NewServer(pathRecordingHandler(clock))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, ok := validators.Lookup("command_injection.time_based")
	if !ok {
		t.Fatal("validator not registered")
	}

	job := timingJob(t, port, "command_injection.time_based")
	env := timingEnv(t, srv, clock)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

// Delta below threshold -> not_reproduced.
func TestTimingNotReproduced(t *testing.T) {
	clock := newPathAwareClock(50, 1000, 1000)
	srv := httptest.NewServer(pathRecordingHandler(clock))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.time_based")

	job := timingJob(t, port, "sqli.time_based")
	env := timingEnv(t, srv, clock)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

// Unstable control -> inconclusive.
func TestTimingUnstableControl(t *testing.T) {
	unstable := &unstableControlClock{
		vals:        make(chan string, 100),
		controlDurs: []time.Duration{50 * time.Millisecond, 5000 * time.Millisecond, 50 * time.Millisecond},
		controlIdx:  0,
		low:         1000 * time.Millisecond,
		high:        5000 * time.Millisecond,
	}
	srv := httptest.NewServer(pathRecordingHandlerGeneric(unstable))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.time_based")

	job := timingJob(t, port, "sqli.time_based")
	env := timingEnv(t, srv, unstable)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

// Status code mismatch between variants -> inconclusive.
func TestTimingStatusCodeMismatch(t *testing.T) {
	clock := newPathAwareClock(50, 1000, 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(timingParam)
		clock.vals <- val
		if val == valHigh {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.time_based")

	job := timingJob(t, port, "sqli.time_based")
	env := timingEnv(t, srv, clock)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

// Bad evidence JSON -> invalid.
func TestTimingInvalidEvidence(t *testing.T) {
	v, _ := validators.Lookup("sqli.time_based")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bad",
			Type:      "sqli.time_based",
			Evidence:  json.RawMessage(`{"not":"valid"}`),
			Proof:     json.RawMessage(`{}`),
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

// Malformed JSON -> invalid.
func TestTimingMalformedJSON(t *testing.T) {
	v, _ := validators.Lookup("command_injection.time_based")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-malformed",
			Type:      "command_injection.time_based",
			Evidence:  json.RawMessage(`not json`),
			Proof:     json.RawMessage(`{}`),
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

// Body dissimilarity between low and high -> inconclusive when required.
func TestTimingBodyDissimilar(t *testing.T) {
	clock := newPathAwareClock(50, 1000, 5000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get(timingParam)
		clock.vals <- val
		w.WriteHeader(http.StatusOK)
		if val == valHigh {
			_, _ = w.Write([]byte(`<html><form><input type="password"></form><p>error denied</p></html>`))
		} else {
			_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
		}
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.time_based")

	job := timingJob(t, port, "sqli.time_based")
	env := timingEnv(t, srv, clock)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive (body dissimilar)", result)
	}
}

// Custom repetitions and threshold from proof.
func TestTimingCustomProof(t *testing.T) {
	clock := newPathAwareClock(50, 500, 2000)
	srv := httptest.NewServer(pathRecordingHandler(clock))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item?id=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": timingParam},
			"payloads": map[string]string{
				"control":    valControl,
				"delay_low":  valLow,
				"delay_high": valHigh,
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"repetitions":             5,
		"min_median_delta_ms":     1000,
		"require_body_similarity": true,
	})

	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-custom",
			Type:      "sqli.time_based",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
	}

	v, _ := validators.Lookup("sqli.time_based")
	env := timingEnv(t, srv, clock)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (custom threshold)", result)
	}
}

// Cheat resistance: the engine builds all three arms from one base_request, so
// the declared injection location must exist there. A location absent from
// base_request is invalid — no second independent request can be supplied.
func TestTimingInjectionLocationAbsent(t *testing.T) {
	ps := strconv.Itoa(9) // unused port; never dialed because parse fails first
	base := "http://app.example.com:" + ps

	// base_request has no "id" query parameter, but the injection names it.
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": timingParam},
			"payloads": map[string]string{
				"control":    valControl,
				"delay_low":  valLow,
				"delay_high": valHigh,
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"repetitions":         3,
		"min_median_delta_ms": 3000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-timing-loc-absent",
			Type:      "sqli.time_based",
			Evidence:  ev,
			Proof:     proof,
		},
	}

	v, _ := validators.Lookup("sqli.time_based")
	env := validators.Env{Clock: validators.WallClock{}}

	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (injection location absent from base_request)", res.Verdict)
	}
}

// G3: timeout_ms bounds a single replay. A high arm that hangs far longer than
// timeout_ms must not block forever — the bounded replay errors and the verdict
// is inconclusive (never a false verified/not_reproduced). Without the per-replay
// context deadline the timing client has no timeout and would hang indefinitely.
func TestTimingTimeoutBoundsHungArm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(timingParam) == valHigh {
			// Hang well past timeout_ms, but release on client cancel so
			// httptest.Server.Close() does not block on this handler.
			select {
			case <-time.After(5 * time.Second):
			case <-r.Context().Done():
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item?id=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": timingParam},
			"payloads": map[string]string{
				"control":    valControl,
				"delay_low":  valLow,
				"delay_high": valHigh,
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"repetitions":         3,
		"min_median_delta_ms": 3000,
		"timeout_ms":          250,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-timeout",
			Type:      "sqli.time_based",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
	}

	v, _ := validators.Lookup("sqli.time_based")
	env := validators.Env{Policy: testEnforcer(t, srv), Artifacts: artifacts.NewStore(), Clock: validators.WallClock{}}

	start := time.Now()
	res, _ := v.Validate(context.Background(), job, env)
	elapsed := time.Since(start)

	if res.Verdict != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive (hung arm bounded by timeout_ms)", res.Verdict)
	}
	// Must be bounded: nowhere near the 5s hang.
	if elapsed > 3*time.Second {
		t.Fatalf("timeout_ms did not bound the replay: took %v", elapsed)
	}
}
