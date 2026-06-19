package validators_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// --- XXE OAST tests ---

func buildXXEJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	xmlBody := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://placeholder.example.com">]><root>&xxe;</root>`

	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/xml/import",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/xml"},
			},
			"body": xmlBody,
		},
		"mutation_slots": map[string]string{
			"oast_url": "xml_external_entity_url",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_dns_or_http",
		"poll_window_seconds": 30,
	})

	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xxe",
			Type:      "xxe.oast",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "xxe-nonce",
	}
}

func TestXXEOASTVerified(t *testing.T) {
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
	v, ok := validators.Lookup("xxe.oast")
	if !ok {
		t.Fatal("validator not registered")
	}
	job := buildXXEJob(t, port)

	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "dns",
					SourceIP:  ip.String(),
					UserAgent: "libxml2/2.9",
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

	// Verify OAST URL was injected into the XML body.
	if len(receivedBody) > 0 {
		body := string(receivedBody)
		if containsSubstring(body, "placeholder.example.com") {
			t.Fatal("OAST URL was not injected into XML body")
		}
		if !containsSubstring(body, "oast.test") {
			t.Fatal("OAST URL not found in XML body")
		}
	}
}

func TestXXEOASTNotReproducedNoCallback(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("xxe.oast")

	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/xml/import",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/xml"},
			},
			"body": `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "https://placeholder.example.com">]><root>&xxe;</root>`,
		},
		"mutation_slots": map[string]string{
			"oast_url": "xml_external_entity_url",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_dns_or_http",
		"poll_window_seconds": 1,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xxe-no-cb",
			Type:      "xxe.oast",
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

func TestXXEOASTInvalidEvidence(t *testing.T) {
	v, _ := validators.Lookup("xxe.oast")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xxe-bad",
			Type:      "xxe.oast",
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

func TestXXEOASTRejectedByPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := restrictiveEnforcer(t, ip, port, "evil.example.com")

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	v, _ := validators.Lookup("xxe.oast")
	job := buildXXEJob(t, port)

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

func TestXXEOASTNotReproducedVerifierOnly(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("xxe.oast")
	job := buildXXEJob(t, port)

	// Inject a verifier-browser callback only.
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
		t.Fatalf("verdict = %q, want not_reproduced (verifier-only)", result)
	}
}

func TestXXEOASTNoBackend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("xxe.oast")
	job := buildXXEJob(t, port)

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

// --- Command Injection OAST tests ---

func buildCmdInjJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/ping",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/x-www-form-urlencoded"},
			},
			"body": "host=placeholder.example.com",
		},
		"mutation_slots": map[string]string{
			"oast_host": "body.host",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_dns",
		"poll_window_seconds": 30,
	})

	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-cmdi",
			Type:      "command_injection.oast",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "cmdi-nonce",
	}
}

func TestCmdInjOASTVerified(t *testing.T) {
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
	v, ok := validators.Lookup("command_injection.oast")
	if !ok {
		t.Fatal("validator not registered")
	}
	job := buildCmdInjJob(t, port)

	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "dns",
					SourceIP:  ip.String(),
					UserAgent: "",
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

	// Verify the OAST domain was injected into the form body.
	if len(receivedBody) > 0 {
		body := string(receivedBody)
		if containsSubstring(body, "placeholder.example.com") {
			t.Fatal("OAST host was not injected into form body")
		}
		if !containsSubstring(body, "oast.test") {
			t.Fatal("OAST host not found in form body")
		}
	}
}

func TestCmdInjOASTNotReproducedNoCallback(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("command_injection.oast")
	job := buildCmdInjJob(t, port)

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

func TestCmdInjOASTInvalidEvidence(t *testing.T) {
	v, _ := validators.Lookup("command_injection.oast")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-cmdi-bad",
			Type:      "command_injection.oast",
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

func TestCmdInjOASTRejectedByPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := restrictiveEnforcer(t, ip, port, "evil.example.com")

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	v, _ := validators.Lookup("command_injection.oast")
	job := buildCmdInjJob(t, port)

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

func TestCmdInjOASTNotReproducedVerifierOnly(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("command_injection.oast")
	job := buildCmdInjJob(t, port)

	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "dns",
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
		t.Fatalf("verdict = %q, want not_reproduced (verifier-only)", result)
	}
}

// --- Blind XSS tests ---

func buildBlindXSSJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/support/contact",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/x-www-form-urlencoded"},
			},
			"body": "message=placeholder",
		},
		"mutation_slots": map[string]string{
			"oast_url": "message",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_http",
		"poll_window_seconds": 900,
	})

	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bxss",
			Type:      "xss.blind",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "bxss-nonce",
	}
}

func TestBlindXSSVerified(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, ok := validators.Lookup("xss.blind")
	if !ok {
		t.Fatal("validator not registered")
	}
	job := buildBlindXSSJob(t, port)

	// Blind XSS does NOT require source attribution — any callback suffices.
	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(30 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "http",
					SourceIP:  "198.51.100.50",
					UserAgent: "Mozilla/5.0 AdminPanel",
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

func TestBlindXSSVerifiedNoAttribution(t *testing.T) {
	// Key distinction from SSRF/XXE: noise-sourced callbacks still verify.
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("xss.blind")
	job := buildBlindXSSJob(t, port)

	// Callback from unknown IP (noise in SSRF terms), but valid for blind XSS.
	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(5 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "https",
					SourceIP:  "192.0.2.99",
					UserAgent: "SomeAdminBrowser",
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
		t.Fatalf("verdict = %q, want verified (no attribution needed for blind XSS)", result)
	}
}

func TestBlindXSSNotReproducedExpired(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("xss.blind")
	job := buildBlindXSSJob(t, port)

	go func() {
		time.Sleep(5 * time.Millisecond)
		clk.Advance(1000 * time.Second) // past 900s window
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

func TestBlindXSSInvalidEvidence(t *testing.T) {
	v, _ := validators.Lookup("xss.blind")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bxss-bad",
			Type:      "xss.blind",
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

func TestBlindXSSRejectedByPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := restrictiveEnforcer(t, ip, port, "evil.example.com")

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	v, _ := validators.Lookup("xss.blind")
	job := buildBlindXSSJob(t, port)

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

func TestBlindXSSNoBackend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	v, _ := validators.Lookup("xss.blind")
	job := buildBlindXSSJob(t, port)

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

// --- test helpers ---

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// restrictiveEnforcer allows only a specific host, not app.example.com.
func restrictiveEnforcer(t *testing.T, ip net.IP, port int, allowHost string) validators.PolicyEnforcer {
	t.Helper()
	resolver := fakeResolver{ips: []net.IP{ip}}
	p := policy.URLPolicy{
		AllowedSchemes:     []string{"http"},
		AllowedHosts:       []string{allowHost},
		AllowedPorts:       []int{port},
		BlockLoopback:      false,
		BlockPrivateIPs:    false,
		InternalAssessment: true,
	}
	checker := policy.NewChecker(p, resolver)
	return &testPolicyEnforcer{checker: checker}
}
