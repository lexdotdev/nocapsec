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

func timingJob(t *testing.T, port int, findingType string) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"requests": map[string]any{
			"control":    map[string]string{"method": "GET", "url": base + "/control"},
			"delay_low":  map[string]string{"method": "GET", "url": base + "/low"},
			"delay_high": map[string]string{"method": "GET", "url": base + "/high"},
		},
		"vulnerable_parameter": "id",
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

// pathChanClock is a Clock that receives request paths from the handler,
// returning a predetermined duration for each path.
type pathChanClock interface {
	validators.Clock
	recordPath(path string)
}

// pathAwareClock returns fixed durations keyed by URL path.
type pathAwareClock struct {
	paths   chan string
	control time.Duration
	low     time.Duration
	high    time.Duration
}

func newPathAwareClock(controlMS, lowMS, highMS int) *pathAwareClock {
	return &pathAwareClock{
		paths:   make(chan string, 100),
		control: time.Duration(controlMS) * time.Millisecond,
		low:     time.Duration(lowMS) * time.Millisecond,
		high:    time.Duration(highMS) * time.Millisecond,
	}
}

func (c *pathAwareClock) Now() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func (c *pathAwareClock) Since(_ time.Time) time.Duration {
	path := <-c.paths
	switch path {
	case "/control":
		return c.control
	case "/low":
		return c.low
	case "/high":
		return c.high
	default:
		return c.control
	}
}

func (c *pathAwareClock) recordPath(path string) {
	c.paths <- path
}

// pathRecordingHandler sends each request's path to the clock channel.
func pathRecordingHandler(clock *pathAwareClock) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clock.paths <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
	})
}

func pathRecordingHandlerGeneric(clock pathChanClock) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clock.recordPath(r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><p>ok</p></html>`))
	})
}

// unstableControlClock cycles through variable control durations.
type unstableControlClock struct {
	paths       chan string
	controlDurs []time.Duration
	controlIdx  int
	low         time.Duration
	high        time.Duration
}

func (c *unstableControlClock) Now() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func (c *unstableControlClock) Since(_ time.Time) time.Duration {
	path := <-c.paths
	switch path {
	case "/control":
		d := c.controlDurs[c.controlIdx%len(c.controlDurs)]
		c.controlIdx++
		return d
	case "/low":
		return c.low
	case "/high":
		return c.high
	default:
		return 50 * time.Millisecond
	}
}

func (c *unstableControlClock) recordPath(path string) {
	c.paths <- path
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
		paths:       make(chan string, 100),
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
		clock.paths <- r.URL.Path
		switch r.URL.Path {
		case "/high":
			w.WriteHeader(http.StatusInternalServerError)
		default:
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
		clock.paths <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/high":
			_, _ = w.Write([]byte(`<html><form><input type="password"></form><p>error denied</p></html>`))
		default:
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
		"requests": map[string]any{
			"control":    map[string]string{"method": "GET", "url": base + "/control"},
			"delay_low":  map[string]string{"method": "GET", "url": base + "/low"},
			"delay_high": map[string]string{"method": "GET", "url": base + "/high"},
		},
		"vulnerable_parameter": "id",
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
