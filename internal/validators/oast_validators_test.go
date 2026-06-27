package validators_test

import (
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

	res := runValidate(t, "xxe.oast", job, env)
	result := res.Verdict
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

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)

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

	res := runValidate(t, "xxe.oast", job, env)
	result := res.Verdict
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

func TestXXEOASTInvalidEvidence(t *testing.T) {
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xxe-bad",
			Type:      "xxe.oast",
			Evidence:  json.RawMessage(`{"not":"valid"}`),
			Proof:     json.RawMessage(`{}`),
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res := runValidate(t, "xxe.oast", job, env)
	result := res.Verdict
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

func TestXXEOASTRejectedByPolicy(t *testing.T) {
	srv := okServer(t)

	ip, port := serverAddr(t, srv)
	pe := restrictiveEnforcer(t, ip, port, "evil.example.com")

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	job := buildXXEJob(t, port)

	env := validators.Env{
		Policy:    pe,
		OAST:      fake,
		Artifacts: artifacts.NewStore(),
		Clock:     clk,
	}

	res := runValidate(t, "xxe.oast", job, env)
	result := res.Verdict
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected", result)
	}
}

func TestXXEOASTNotReproducedVerifierOnly(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
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

	res := runValidate(t, "xxe.oast", job, env)
	result := res.Verdict
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (verifier-only)", result)
	}
}

func TestXXEOASTNoBackend(t *testing.T) {
	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	job := buildXXEJob(t, port)

	env := validators.Env{
		Policy:    pe,
		OAST:      nil,
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	res := runValidate(t, "xxe.oast", job, env)
	result := res.Verdict
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

	res := runValidate(t, "command_injection.oast", job, env)
	result := res.Verdict
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}

	// OAST domain reaches the form body.
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

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
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

	res := runValidate(t, "command_injection.oast", job, env)
	result := res.Verdict
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

func TestCmdInjOASTInvalidEvidence(t *testing.T) {
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-cmdi-bad",
			Type:      "command_injection.oast",
			Evidence:  json.RawMessage(`{"not":"valid"}`),
			Proof:     json.RawMessage(`{}`),
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res := runValidate(t, "command_injection.oast", job, env)
	result := res.Verdict
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

func TestCmdInjOASTRejectedByPolicy(t *testing.T) {
	srv := okServer(t)

	ip, port := serverAddr(t, srv)
	pe := restrictiveEnforcer(t, ip, port, "evil.example.com")

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	job := buildCmdInjJob(t, port)

	env := validators.Env{
		Policy:    pe,
		OAST:      fake,
		Artifacts: artifacts.NewStore(),
		Clock:     clk,
	}

	res := runValidate(t, "command_injection.oast", job, env)
	result := res.Verdict
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected", result)
	}
}

func TestCmdInjOASTNotReproducedVerifierOnly(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
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

	res := runValidate(t, "command_injection.oast", job, env)
	result := res.Verdict
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (verifier-only)", result)
	}
}

// Token mode preserves shell breakout.
func buildCmdInjTokenJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	body := "--X\r\nContent-Disposition: form-data; name=\"file\"; " +
		"filename=\"a;curl${IFS}{{oast_url}};b.png\"\r\nContent-Type: image/png\r\n\r\nPNG\r\n--X--\r\n"
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "POST",
			"url":    base + "/api/upload",
			"headers": []map[string]string{
				{"name": "content-type", "value": "multipart/form-data; boundary=X"},
			},
			"body": body,
		},
		"mutation_slots": map[string]string{
			"oast_host": "{{oast_url}}",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":     "oast_interaction",
		"poll_window_seconds": 30,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-cmdi-token",
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
		Nonce: "cmdi-token-nonce",
	}
}

// Token mode reaches multipart filename.
func TestCmdInjOASTTokenBreakoutVerified(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		receivedBody = buf[:n]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	job := buildCmdInjTokenJob(t, port)

	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			tok := findFakeToken(fake)
			if tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{
					Protocol:  "http",
					SourceIP:  ip.String(),
					UserAgent: "curl/8.0",
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

	res := runValidate(t, "command_injection.oast", job, env)
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}

	// Shell breakout must survive.
	body := string(receivedBody)
	if !containsSubstring(body, "curl${IFS}") || !containsSubstring(body, "oast.test") {
		t.Fatalf("OAST URL not placed inside the shell breakout; got body: %q", body)
	}
	if containsSubstring(body, "{{oast_url}}") {
		t.Fatal("token {{oast_url}} was not substituted")
	}
}

// Token mode supports query DNS.
func TestCmdInjOASTTokenQueryHostVerified(t *testing.T) {
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

	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"request": map[string]any{
			"method": "GET",
			"url":    base + "/diag?host=x;nslookup${IFS}{{oast_host}};y",
		},
		"mutation_slots": map[string]string{"oast_host": "{{oast_host}}"},
	})
	proof, _ := json.Marshal(map[string]any{"expected_signal": "oast_interaction", "poll_window_seconds": 30})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-cmdi-token-q",
			Type:      "command_injection.oast",
			Target: evidence.Target{
				ExpectedOrigin: base, AllowedHosts: []string{"app.example.com"},
				AllowedSchemes: []string{"http"}, AllowedPorts: []int{port},
			},
			Evidence: ev, Proof: proof,
		},
		Nonce: "cmdi-q-nonce",
	}

	go func() {
		time.Sleep(2 * time.Millisecond)
		for i := 0; i < 200; i++ {
			if tok := findFakeToken(fake); tok != "" {
				clk.Advance(3 * time.Second)
				fake.AddInteraction(tok, oast.Interaction{Protocol: "dns", SourceIP: ip.String(), Timestamp: clk.Now()})
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	env := validators.Env{Policy: pe, OAST: fake, Artifacts: artifacts.NewStore(), Clock: clk, PollConfig: fastPollConfig()}
	res := runValidate(t, "command_injection.oast", job, env)
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
	if !containsSubstring(gotURL, "nslookup") || !containsSubstring(gotURL, "oast.test") || containsSubstring(gotURL, "{{oast_host}}") {
		t.Fatalf("oast_host token not substituted into query breakout; got %q", gotURL)
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

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	job := buildBlindXSSJob(t, port)

	// Blind XSS accepts any callback.
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

	res := runValidate(t, "xss.blind", job, env)
	result := res.Verdict
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

func TestBlindXSSVerifiedNoAttribution(t *testing.T) {
	// Noise callbacks still verify.
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	job := buildBlindXSSJob(t, port)

	// Unknown-source callback is valid.
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

	res := runValidate(t, "xss.blind", job, env)
	result := res.Verdict
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (no attribution needed for blind XSS)", result)
	}
}

func TestBlindXSSNotReproducedExpired(t *testing.T) {
	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")

	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
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

	res := runValidate(t, "xss.blind", job, env)
	result := res.Verdict
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

func TestBlindXSSInvalidEvidence(t *testing.T) {
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bxss-bad",
			Type:      "xss.blind",
			Evidence:  json.RawMessage(`{"not":"valid"}`),
			Proof:     json.RawMessage(`{}`),
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res := runValidate(t, "xss.blind", job, env)
	result := res.Verdict
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

func TestBlindXSSRejectedByPolicy(t *testing.T) {
	srv := okServer(t)

	ip, port := serverAddr(t, srv)
	pe := restrictiveEnforcer(t, ip, port, "evil.example.com")

	clk := newTestOASTClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	fake := oast.NewFake(clk, "oast.test")
	job := buildBlindXSSJob(t, port)

	env := validators.Env{
		Policy:    pe,
		OAST:      fake,
		Artifacts: artifacts.NewStore(),
		Clock:     clk,
	}

	res := runValidate(t, "xss.blind", job, env)
	result := res.Verdict
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected", result)
	}
}

func TestBlindXSSNoBackend(t *testing.T) {
	srv := okServer(t)

	_, port := serverAddr(t, srv)
	pe := ssrfEnforcer(t, srv)
	job := buildBlindXSSJob(t, port)

	env := validators.Env{
		Policy:    pe,
		OAST:      nil,
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	res := runValidate(t, "xss.blind", job, env)
	result := res.Verdict
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

// restrictiveEnforcer narrows host scope.
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
