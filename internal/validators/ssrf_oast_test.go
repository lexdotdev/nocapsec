package validators_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// testOASTClock is a controllable clock for OAST tests.
type testOASTClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestOASTClock(t time.Time) *testOASTClock {
	return &testOASTClock{now: t}
}

func (c *testOASTClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testOASTClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

func (c *testOASTClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fastPollConfig returns a PollConfig suitable for tests (1ms real sleeps).
func fastPollConfig() *oast.PollConfig {
	return &oast.PollConfig{
		InitialWait: 1 * time.Millisecond,
		MinInterval: 1 * time.Millisecond,
		MaxInterval: 1 * time.Millisecond,
		Multiplier:  1.0,
	}
}

// ssrfEnforcer builds a PolicyEnforcer that allows the httptest server.
func ssrfEnforcer(t *testing.T, srv *httptest.Server) validators.PolicyEnforcer {
	t.Helper()
	ip, port := serverAddr(t, srv)
	resolver := fakeResolver{ips: []net.IP{ip}}
	p := policy.URLPolicy{
		AllowedSchemes:     []string{"http"},
		AllowedHosts:       []string{"app.example.com"},
		AllowedPorts:       []int{port},
		AllowRedirects:     true,
		MaxRedirects:       5,
		BlockLoopback:      false,
		BlockPrivateIPs:    false,
		InternalAssessment: true,
	}
	checker := policy.NewChecker(p, resolver)
	return &testPolicyEnforcer{checker: checker}
}

func buildSSRFJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/fetch",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/json"},
			},
			"body": `{"url":"https://placeholder.example.com"}`,
		},
		"injection_location": map[string]string{
			"kind":         "json_body",
			"json_pointer": "/url",
		},
		"expected_protocols": []string{"dns", "http", "https"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":             "oast_interaction",
		"poll_window_seconds":         30,
		"require_source_not_verifier": true,
	})

	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-ssrf",
			Type:      "ssrf.oast",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "testnonce",
	}
}

// TestSSRFOASTVerified: target server fetches the OAST URL -> verified.
func TestSSRFOASTVerified(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"fetched"}`))
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, ok := validators.Lookup("ssrf.oast")
	if !ok {
		t.Fatal("validator not registered")
	}

	job := buildSSRFJob(t, port)

	// Inject a target-sourced callback after token allocation.
	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "dns",
					SourceIP:  ip.String(),
					UserAgent: "Python-urllib/3.11",
					Timestamp: clk.Now(),
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	env := validators.Env{
		Policy:     pe,
		OAST:       fake,
		Artifacts:  artifacts.NewStore(),
		Clock:      clk,
		PollConfig: fastPollConfig(),
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

// TestSSRFOASTNotReproducedNoCallback: no OAST callback -> not_reproduced.
func TestSSRFOASTNotReproducedNoCallback(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("ssrf.oast")

	// Build a job with a very short poll window.
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/fetch",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/json"},
			},
			"body": `{"url":"https://placeholder.example.com"}`,
		},
		"injection_location": map[string]string{
			"kind":         "json_body",
			"json_pointer": "/url",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_interaction",
		"poll_window_seconds": 1, // 1 second window
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-ssrf-no-cb",
			Type:      "ssrf.oast",
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

	// Advance clock past the window after allocation happens inside Validate.
	go func() {
		time.Sleep(5 * time.Millisecond)
		clk.Advance(200 * time.Second)
	}()

	env := validators.Env{
		Policy:     pe,
		OAST:       fake,
		Artifacts:  artifacts.NewStore(),
		Clock:      clk,
		PollConfig: fastPollConfig(),
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

// TestSSRFOASTNotReproducedVerifierOnly: only verifier-browser callback -> not_reproduced.
func TestSSRFOASTNotReproducedVerifierOnly(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("ssrf.oast")
	job := buildSSRFJob(t, port)

	// Inject a verifier-browser callback (HeadlessChrome UA, non-target IP).
	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "http",
					SourceIP:  "203.0.113.99",
					UserAgent: "Mozilla/5.0 HeadlessChrome/125.0.0.0",
					Timestamp: clk.Now(),
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	env := validators.Env{
		Policy:     pe,
		OAST:       fake,
		Artifacts:  artifacts.NewStore(),
		Clock:      clk,
		PollConfig: fastPollConfig(),
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (verifier-only callbacks)", result)
	}
}

// TestSSRFOASTInvalidEvidence: bad evidence JSON -> invalid.
func TestSSRFOASTInvalidEvidence(t *testing.T) {
	v, _ := validators.Lookup("ssrf.oast")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bad-ev",
			Type:      "ssrf.oast",
			Evidence:  json.RawMessage(`{"not":"valid ssrf evidence"}`),
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

// TestSSRFOASTMissingInjectionLocation: no injection location -> invalid.
func TestSSRFOASTMissingInjectionLocation(t *testing.T) {
	v, _ := validators.Lookup("ssrf.oast")
	ev, _ := json.Marshal(map[string]any{
		"request":            map[string]string{"method": "POST", "url": "http://a/fetch", "body": `{"url":"x"}`},
		"injection_location": map[string]string{},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_interaction",
		"poll_window_seconds": 10,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-no-loc",
			Type:      "ssrf.oast",
			Evidence:  ev,
			Proof:     proof,
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

// TestSSRFOASTNoOASTBackend: nil OAST -> inconclusive.
func TestSSRFOASTNoOASTBackend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("ssrf.oast")
	job := buildSSRFJob(t, port)

	env := validators.Env{
		Policy:    pe,
		OAST:      nil,
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

// TestSSRFOASTRejectedByPolicy: out-of-scope URL -> rejected.
func TestSSRFOASTRejectedByPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	resolver := fakeResolver{ips: []net.IP{ip}}
	p := policy.URLPolicy{
		AllowedSchemes:     []string{"http"},
		AllowedHosts:       []string{"evil.example.com"},
		AllowedPorts:       []int{port},
		BlockLoopback:      false,
		BlockPrivateIPs:    false,
		InternalAssessment: true,
	}
	checker := policy.NewChecker(p, resolver)
	pe := &testPolicyEnforcer{checker: checker}

	v, _ := validators.Lookup("ssrf.oast")
	job := buildSSRFJob(t, port)

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	env := validators.Env{
		Policy:    pe,
		OAST:      fake,
		Artifacts: artifacts.NewStore(),
		Clock:     clk,
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected", result)
	}
}

// TestSSRFOASTNestedJSONPointer: injection into a nested JSON path.
func TestSSRFOASTNestedJSONPointer(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("ssrf.oast")

	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/api/proxy",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/json"},
			},
			"body": `{"config":{"target":"https://placeholder"},"action":"fetch"}`,
		},
		"injection_location": map[string]string{
			"kind":         "json_body",
			"json_pointer": "/config/target",
		},
		"expected_protocols": []string{"dns", "http", "https"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_interaction",
		"poll_window_seconds": 30,
	})

	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-ssrf-nested",
			Type:      "ssrf.oast",
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

	// Inject target-sourced callback.
	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "http",
					SourceIP:  ip.String(),
					UserAgent: "Go-http-client/1.1",
					Timestamp: clk.Now(),
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	env := validators.Env{
		Policy:     pe,
		OAST:       fake,
		Artifacts:  artifacts.NewStore(),
		Clock:      clk,
		PollConfig: fastPollConfig(),
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}

	// Verify the body was patched at the right path.
	if len(receivedBody) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(receivedBody, &parsed); err == nil {
			cfg, _ := parsed["config"].(map[string]any)
			if cfg != nil {
				target, _ := cfg["target"].(string)
				if target == "https://placeholder" {
					t.Fatal("OAST URL was not injected into nested path")
				}
			}
			if action, _ := parsed["action"].(string); action != "fetch" {
				t.Fatalf("action field changed: %q", action)
			}
		}
	}
}

func TestSSRFOASTQueryInjection(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	var gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("ssrf.oast")

	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "GET",
			"url":    base + "/proxy?url=http%3A%2F%2Fplaceholder.invalid&mode=raw",
		},
		"injection_location": map[string]string{
			"kind": "query",
			"name": "url",
		},
		"expected_protocols": []string{"http"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_interaction",
		"poll_window_seconds": 30,
	})

	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-ssrf-query",
			Type:      "ssrf.oast",
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

	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "http",
					SourceIP:  ip.String(),
					UserAgent: "Go-http-client/1.1",
					Timestamp: clk.Now(),
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	env := validators.Env{
		Policy:     pe,
		OAST:       fake,
		Artifacts:  artifacts.NewStore(),
		Clock:      clk,
		PollConfig: fastPollConfig(),
	}

	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}

	parsed, err := url.Parse(gotURL)
	if err != nil {
		t.Fatalf("parse replay URL: %v", err)
	}
	values := parsed.Query()
	if values.Get("mode") != "raw" {
		t.Fatalf("mode changed: %q", values.Get("mode"))
	}
	if values.Get("url") == "http://placeholder.invalid" || values.Get("url") == "" {
		t.Fatalf("url was not injected: %q", values.Get("url"))
	}
}

// TestSSRFOASTNoiseCallbackIgnored: only noise callbacks -> not_reproduced.
func TestSSRFOASTNoiseCallbackIgnored(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("ssrf.oast")
	job := buildSSRFJob(t, port)

	// Inject a noise callback (unrelated IP, unrelated UA).
	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "http",
					SourceIP:  "198.51.100.1",
					UserAgent: "Shodan",
					Timestamp: clk.Now(),
				})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	env := validators.Env{
		Policy:     pe,
		OAST:       fake,
		Artifacts:  artifacts.NewStore(),
		Clock:      clk,
		PollConfig: fastPollConfig(),
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (noise-only callbacks)", result)
	}
}

// findFakeToken retrieves the first allocated token ID from the fake.
func findFakeToken(f *oast.Fake) string {
	for id := 1; id <= 20; id++ {
		corrID := fakeCorrID(id)
		_, err := f.Poll(context.Background(), corrID, time.Time{})
		if err == nil {
			return corrID
		}
	}
	return ""
}

func fakeCorrID(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 4 {
		s = "0" + s
	}
	return "fake-" + s
}
