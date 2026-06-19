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

// fakeBrowser returns a predetermined BrowserResult.
type fakeBrowser struct {
	result browser.BrowserResult
	err    error
}

func (f *fakeBrowser) Run(_ context.Context, _ browser.BrowserJob) (browser.BrowserResult, error) {
	return f.result, f.err
}

// --- xss.reflected tests ---

func reflectedJob(t *testing.T, port int, nonce string) validators.Job {
	t.Helper()
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	ev, _ := json.Marshal(map[string]any{
		"entrypoint": map[string]string{
			"method": "GET",
			"url":    origin + "/search?q=payload",
		},
		"payload_marker": "VERIFIER_XSS_" + nonce,
		"trigger": map[string]any{
			"kind": "browser_navigate",
			"wait": "load_or_network_idle",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"accepted_signals":          []string{"javascript_dialog", "console_log"},
		"expected_message_contains": "VERIFIER_XSS_" + nonce,
		"expected_execution_origin": origin,
		"timeout_ms":                5000,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xss-reflected",
			Type:      "xss.reflected",
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

func TestXSSReflectedVerified_Dialog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "abc123"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search?q=payload"}},
		Dialogs: []browser.DialogEvent{{
			Type:         "alert",
			Message:      "VERIFIER_XSS_" + nonce,
			SourceOrigin: origin,
		}},
		FinalURL: origin + "/search?q=payload",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, ok := validators.Lookup("xss.reflected")
	if !ok {
		t.Fatal("validator not registered")
	}

	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

func TestXSSReflectedVerified_ConsoleLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "console789"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search"}},
		Console: []browser.ConsoleEvent{{
			Text:      "VERIFIER_XSS_" + nonce,
			SourceURL: origin + "/search?q=payload",
		}},
		FinalURL: origin + "/search?q=payload",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

func TestXSSReflectedRejected_VerifierHookDialog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "hook456"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search"}},
		Dialogs: []browser.DialogEvent{{
			Type:             "alert",
			Message:          "VERIFIER_XSS_" + nonce,
			SourceOrigin:     origin,
			FromVerifierHook: true, // must be rejected
		}},
		FinalURL: origin + "/search",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (verifier hook)", result)
	}
}

func TestXSSReflectedNotReproduced_WrongNonce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "real_nonce"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search"}},
		Dialogs: []browser.DialogEvent{{
			Type:         "alert",
			Message:      "wrong_nonce_value",
			SourceOrigin: origin,
		}},
		FinalURL: origin + "/search",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (wrong nonce)", result)
	}
}

func TestXSSReflectedNotReproduced_WrongOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "origintest"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search"}},
		Dialogs: []browser.DialogEvent{{
			Type:         "alert",
			Message:      "VERIFIER_XSS_" + nonce,
			SourceOrigin: "http://evil.com", // wrong origin
		}},
		FinalURL: origin + "/search",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (wrong origin)", result)
	}
}

func TestXSSReflectedNotReproduced_ExternalNav(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "navtest"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{
			{Origin: origin, URL: origin + "/search"},
			{Origin: "http://evil.com", URL: "http://evil.com/phish"},
		},
		Dialogs: []browser.DialogEvent{{
			Type:         "alert",
			Message:      "VERIFIER_XSS_" + nonce,
			SourceOrigin: origin,
		}},
		FinalURL: "http://evil.com/phish",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (external nav)", result)
	}
}

func TestXSSReflectedNotReproduced_NoSignals(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "nosig"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search"}},
		FinalURL:   origin + "/search",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (no signals)", result)
	}
}

func TestXSSReflectedRejected_JavascriptScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "jsscheme"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	// Craft a job with a javascript: scheme entrypoint.
	ev, _ := json.Marshal(map[string]any{
		"entrypoint": map[string]string{
			"method": "GET",
			"url":    "javascript:alert(1)",
		},
		"payload_marker": "VERIFIER_XSS_" + nonce,
		"trigger": map[string]any{
			"kind": "browser_navigate",
			"wait": "load_or_network_idle",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"accepted_signals":          []string{"javascript_dialog"},
		"expected_message_contains": "VERIFIER_XSS_" + nonce,
		"expected_execution_origin": origin,
		"timeout_ms":                5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xss-jsscheme",
			Type:      "xss.reflected",
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
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected (javascript: scheme)", result)
	}
}

func TestXSSReflectedInconclusive_BrowserError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "browserr"

	fb := &fakeBrowser{err: fmt.Errorf("chromium crashed")}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err == nil {
		t.Fatal("expected error")
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

func TestXSSReflectedNotReproduced_ConsoleEmptySourceURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "emptysrc"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/search"}},
		Console: []browser.ConsoleEvent{{
			Text:      "VERIFIER_XSS_" + nonce,
			SourceURL: "", // empty = reject
		}},
		FinalURL: origin + "/search",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.reflected")
	res, err := v.Validate(context.Background(), reflectedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (empty console source)", result)
	}
}

// --- xss.stored tests ---

func storedJob(t *testing.T, port int, nonce string) validators.Job {
	t.Helper()
	origin := fmt.Sprintf("http://app.example.com:%d", port)
	ev, _ := json.Marshal(map[string]any{
		"setup": []map[string]any{{
			"method": "POST",
			"url":    origin + "/profile",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/x-www-form-urlencoded"},
			},
			"body": "display_name=<script>alert('VERIFIER_STORED_XSS_" + nonce + "')</script>",
		}},
		"trigger": map[string]string{
			"method": "GET",
			"url":    origin + "/users/me",
		},
		"vulnerable_parameter": "display_name",
		"payload_marker":       "VERIFIER_STORED_XSS_" + nonce,
	})
	proof, _ := json.Marshal(map[string]any{
		"accepted_signals":          []string{"javascript_dialog", "console_log"},
		"expected_message_contains": "VERIFIER_STORED_XSS_" + nonce,
		"expected_execution_origin": origin,
		"timeout_ms":                5000,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xss-stored",
			Type:      "xss.stored",
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

func TestXSSStoredVerified(t *testing.T) {
	var stored string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/profile":
			_ = r.ParseForm()
			stored = r.FormValue("display_name")
			w.WriteHeader(http.StatusOK)
		case "/users/me":
			_, _ = fmt.Fprintf(w, "<html><body>%s</body></html>", stored)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "stored123"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/users/me"}},
		Dialogs: []browser.DialogEvent{{
			Type:         "alert",
			Message:      "VERIFIER_STORED_XSS_" + nonce,
			SourceOrigin: origin,
		}},
		FinalURL: origin + "/users/me",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, ok := validators.Lookup("xss.stored")
	if !ok {
		t.Fatal("validator not registered")
	}

	res, err := v.Validate(context.Background(), storedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

func TestXSSStoredNotReproduced_NoSignal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "nosigstored"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/users/me"}},
		FinalURL:   origin + "/users/me",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.stored")
	res, err := v.Validate(context.Background(), storedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

func TestXSSStoredInconclusive_SetupFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "setupfail"

	fb := &fakeBrowser{result: browser.BrowserResult{}}
	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.stored")
	res, err := v.Validate(context.Background(), storedJob(t, port, nonce), env)
	result := res.Verdict
	if err == nil {
		t.Fatal("expected error from setup failure")
	}
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

func TestXSSStoredVerified_WithCleanup(t *testing.T) {
	var profileCalls, cleanupCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/profile" && r.Method == http.MethodPost {
			profileCalls++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "cleanup456"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	// Build a job with explicit cleanup in side_effects.
	ev, _ := json.Marshal(map[string]any{
		"setup": []map[string]any{{
			"method": "POST",
			"url":    origin + "/profile",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/x-www-form-urlencoded"},
			},
			"body": "display_name=payload_" + nonce,
		}},
		"trigger": map[string]string{
			"method": "GET",
			"url":    origin + "/users/me",
		},
		"vulnerable_parameter": "display_name",
		"payload_marker":       "VERIFIER_STORED_XSS_" + nonce,
		"cleanup": []map[string]any{{
			"method": "POST",
			"url":    origin + "/profile",
			"headers": []map[string]string{
				{"name": "content-type", "value": "application/x-www-form-urlencoded"},
			},
			"body": "display_name=clean",
		}},
	})
	proof, _ := json.Marshal(map[string]any{
		"accepted_signals":          []string{"javascript_dialog"},
		"expected_message_contains": "VERIFIER_STORED_XSS_" + nonce,
		"expected_execution_origin": origin,
		"timeout_ms":                5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xss-stored-cleanup",
			Type:      "xss.stored",
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

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/users/me"}},
		Dialogs: []browser.DialogEvent{{
			Type:         "alert",
			Message:      "VERIFIER_STORED_XSS_" + nonce,
			SourceOrigin: origin,
		}},
		FinalURL: origin + "/users/me",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.stored")
	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}

	// Setup (1) + cleanup (1) = 2 POST calls to /profile.
	_ = cleanupCalls
	if profileCalls < 2 {
		t.Fatalf("profileCalls = %d, want >= 2 (setup + cleanup)", profileCalls)
	}
}

func TestXSSStoredRejected_DataScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "datascheme"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	ev, _ := json.Marshal(map[string]any{
		"setup": []map[string]any{{
			"method": "POST",
			"url":    origin + "/profile",
			"body":   "display_name=x",
		}},
		"trigger": map[string]string{
			"method": "GET",
			"url":    "data:text/html,<script>alert(1)</script>",
		},
		"vulnerable_parameter": "display_name",
		"payload_marker":       "x",
	})
	proof, _ := json.Marshal(map[string]any{
		"accepted_signals":          []string{"javascript_dialog"},
		"expected_message_contains": nonce,
		"expected_execution_origin": origin,
		"timeout_ms":                5000,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-xss-stored-data",
			Type:      "xss.stored",
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
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.stored")
	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected (data: trigger)", result)
	}
}

func TestXSSStoredNotReproduced_VerifierHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	nonce := "hookstored"
	origin := fmt.Sprintf("http://app.example.com:%d", port)

	fb := &fakeBrowser{result: browser.BrowserResult{
		Navigation: []browser.NavEvent{{Origin: origin, URL: origin + "/users/me"}},
		Dialogs: []browser.DialogEvent{{
			Type:             "alert",
			Message:          "VERIFIER_STORED_XSS_" + nonce,
			SourceOrigin:     origin,
			FromVerifierHook: true,
		}},
		FinalURL: origin + "/users/me",
	}}

	env := validators.Env{
		Browser:   fb,
		Policy:    makeEnforcer(t, ip, port),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	v, _ := validators.Lookup("xss.stored")
	res, err := v.Validate(context.Background(), storedJob(t, port, nonce), env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (verifier hook)", result)
	}
}

// --- helpers ---

func makeEnforcer(t *testing.T, ip net.IP, port int) validators.PolicyEnforcer {
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
