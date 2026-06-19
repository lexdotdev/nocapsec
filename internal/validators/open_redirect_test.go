package validators_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func redirectJob(t *testing.T, port int, nonce, externalOrigin string) validators.Job {
	t.Helper()
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	ev, _ := json.Marshal(map[string]any{
		"entrypoint": map[string]string{
			"method": "GET",
			"url":    origin + "/login?next=" + externalOrigin + "/redir/" + nonce,
		},
		"redirect_parameter":      "next",
		"expected_initial_origin": origin,
		"expected_final_origin":   externalOrigin,
		"redirect_kind":           "server_or_client",
		"max_hops":                5,
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":               "browser_final_url_or_oast_http",
		"require_initial_target_origin": true,
		"require_final_external_origin": true,
		"timeout_ms":                    8000,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-open-redirect",
			Type:      "open_redirect",
			Target: evidence.Target{
				ExpectedOrigin: origin,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: nonce,
	}
}

func redirectEnforcer(t *testing.T, ip net.IP, port int) validators.PolicyEnforcer {
	t.Helper()
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

func TestOpenRedirectVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "redir123"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/login?next=http://evil.example.com:8080/redir/" + nonce},
			{Origin: externalOrigin, URL: externalOrigin + "/redir/" + nonce},
		},
		FinalURL: externalOrigin + "/redir/" + nonce,
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, ok := validators.Lookup("open_redirect")
	if !ok {
		t.Fatal("validator not registered")
	}

	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

func TestOpenRedirectNotReproduced_NoTransition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "notrans"
	externalOrigin := "http://evil.example.com:8080"

	// Only external nav events -- no transition from target.
	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: externalOrigin, URL: externalOrigin + "/redir/" + nonce},
		},
		FinalURL: externalOrigin + "/redir/" + nonce,
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (no transition)", result)
	}
}

func TestOpenRedirectNotReproduced_NonceMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "missing_nonce"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	// Final URL does not contain the nonce.
	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/login?next=x"},
			{Origin: externalOrigin, URL: externalOrigin + "/other"},
		},
		FinalURL: externalOrigin + "/other",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (nonce missing)", result)
	}
}

func TestOpenRedirectNotReproduced_FinalOriginWrong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "wrongfinal"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	// Final URL lands on target, not external.
	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/login?next=x"},
		},
		FinalURL: origin + "/dashboard?t=" + nonce,
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (final origin wrong)", result)
	}
}

func TestOpenRedirectRejected_JavascriptScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "jsredir"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	ev, _ := json.Marshal(map[string]any{
		"entrypoint": map[string]string{
			"method": "GET",
			"url":    "javascript:alert(1)",
		},
		"redirect_parameter":      "next",
		"expected_initial_origin": origin,
		"expected_final_origin":   externalOrigin,
		"redirect_kind":           "client",
		"max_hops":                5,
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":               "browser_final_url_or_oast_http",
		"require_initial_target_origin": true,
		"require_final_external_origin": true,
		"timeout_ms":                    5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-redirect-js",
			Type:      "open_redirect",
			Target: evidence.Target{
				ExpectedOrigin: origin,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: nonce,
	}

	fb := &fakeBrowser{result: browser.BrowserResult{}}
	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected (javascript: scheme)", result)
	}
}

func TestOpenRedirectRejected_DataScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "dataredir"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	ev, _ := json.Marshal(map[string]any{
		"entrypoint": map[string]string{
			"method": "GET",
			"url":    "data:text/html,<script>location='http://evil.example.com'</script>",
		},
		"redirect_parameter":      "next",
		"expected_initial_origin": origin,
		"expected_final_origin":   externalOrigin,
		"redirect_kind":           "client",
		"max_hops":                5,
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_signal":               "browser_final_url_or_oast_http",
		"require_initial_target_origin": true,
		"require_final_external_origin": true,
		"timeout_ms":                    5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-redirect-data",
			Type:      "open_redirect",
			Target: evidence.Target{
				ExpectedOrigin: origin,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: nonce,
	}

	fb := &fakeBrowser{result: browser.BrowserResult{}}
	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected (data: scheme)", result)
	}
}

func TestOpenRedirectRejected_FinalJavascriptScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "finjsredir"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/login?next=javascript:alert(1)"},
		},
		FinalURL: "javascript:alert('" + nonce + "')",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected (final javascript: scheme)", result)
	}
}

func TestOpenRedirectInconclusive_BrowserError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "browsererr"
	externalOrigin := "http://evil.example.com:8080"

	fb := &fakeBrowser{err: fmt.Errorf("chromium crashed")}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err == nil {
		t.Fatal("expected error")
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

func TestOpenRedirectInvalid_BadEvidence(t *testing.T) {
	v, _ := validators.Lookup("open_redirect")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bad-ev",
			Type:      "open_redirect",
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

func TestOpenRedirectInvalid_BadOrigin(t *testing.T) {
	v, _ := validators.Lookup("open_redirect")
	ev, _ := json.Marshal(map[string]any{
		"entrypoint":              map[string]string{"method": "GET", "url": "http://a/b"},
		"expected_initial_origin": "not-a-url",
		"expected_final_origin":   "http://evil.example.com",
	})
	proof, _ := json.Marshal(map[string]any{
		"timeout_ms": 5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bad-origin",
			Type:      "open_redirect",
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

func TestOpenRedirectNotReproduced_NoNavEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "nonav"
	externalOrigin := "http://evil.example.com:8080"

	fb := &fakeBrowser{result: browser.BrowserResult{
		FinalURL: externalOrigin + "/redir/" + nonce,
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (no nav events)", result)
	}
}

func TestOpenRedirectNotReproduced_ExceedsMaxHops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "maxhops"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	// Create evidence with max_hops=2 but the redirect chain is longer.
	ev, _ := json.Marshal(map[string]any{
		"entrypoint": map[string]string{
			"method": "GET",
			"url":    origin + "/login?next=" + externalOrigin + "/redir/" + nonce,
		},
		"redirect_parameter":      "next",
		"expected_initial_origin": origin,
		"expected_final_origin":   externalOrigin,
		"redirect_kind":           "server_or_client",
		"max_hops":                2,
	})
	proof, _ := json.Marshal(map[string]any{
		"timeout_ms": 5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-maxhops",
			Type:      "open_redirect",
			Target: evidence.Target{
				ExpectedOrigin: origin,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: nonce,
	}

	// 3 nav events but max_hops=2, so the external one at index 2 is past the limit.
	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/login"},
			{Origin: origin, URL: origin + "/auth/callback"},
			{Origin: externalOrigin, URL: externalOrigin + "/redir/" + nonce},
		},
		FinalURL: externalOrigin + "/redir/" + nonce,
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (exceeded max hops)", result)
	}
}

func TestOpenRedirectVerified_MultiHop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "multihop"
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	externalOrigin := "http://evil.example.com:8080"

	// target -> target -> external, within max_hops=5
	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/login"},
			{Origin: origin, URL: origin + "/oauth/callback"},
			{Origin: externalOrigin, URL: externalOrigin + "/redir/" + nonce},
		},
		FinalURL: externalOrigin + "/redir/" + nonce,
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    redirectEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("open_redirect")
	res, err := v.Validate(context.Background(), redirectJob(t, port, nonce, externalOrigin), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (multi-hop)", result)
	}
}
