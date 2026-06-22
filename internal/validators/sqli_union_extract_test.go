package validators_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

const extractNonce = "ncx-canary-7f3a"

func buildUnionExtractJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"setup_resource": map[string]any{
			"method":  "POST",
			"url":     base + "/api/auth/register",
			"headers": []map[string]string{{"name": "content-type", "value": "application/json"}},
			"body":    `{"email":"canary_{{nonce}}@example.test","password":"pw12345","full_name":"{{nonce}}"}`,
		},
		"base_request": map[string]string{"method": "GET", "url": base + "/api/products/search?q=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "q"},
			"payloads": map[string]string{
				"control": "nomatch_zzz",
				"extract": "nomatch_zzz' UNION SELECT id, full_name, email, 0, '', '', 0 FROM users-- -",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_extract":        true,
		"expected_marker_absent_in_control": true,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-sqli-union-extract",
			Type:      "sqli.union_extract",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: extractNonce,
	}
}

func unionExtractEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

// vulnerableExtractApp simulates a register endpoint (stores full_name) and a
// search endpoint whose UNION payload leaks stored users.full_name in-band.
// leakControl=true makes even the benign control leak (to test attribution).
// registerStatus overrides the register response status.
func vulnerableExtractApp(leakControl bool, registerStatus int) http.Handler {
	var mu sync.Mutex
	var names []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		if fn, ok := req["full_name"].(string); ok && fn != "" {
			mu.Lock()
			names = append(names, fn)
			mu.Unlock()
		}
		w.WriteHeader(registerStatus)
		_, _ = w.Write([]byte(`{"id":1}`))
	})
	mux.HandleFunc("/api/products/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		leak := strings.Contains(strings.ToUpper(q), "UNION") || leakControl
		w.WriteHeader(http.StatusOK)
		mu.Lock()
		defer mu.Unlock()
		if leak {
			out, _ := json.Marshal(map[string]any{"leaked": names})
			_, _ = w.Write(out)
			return
		}
		_, _ = w.Write([]byte(`{"products":[]}`))
	})
	return mux
}

func runUnionExtract(t *testing.T, srv *httptest.Server) verdict.Verdict {
	t.Helper()
	_, port := serverAddr(t, srv)
	v, ok := validators.Lookup("sqli.union_extract")
	if !ok {
		t.Fatal("validator not registered")
	}
	res, err := v.Validate(context.Background(), buildUnionExtractJob(t, port), unionExtractEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return res.Verdict
}

func TestSQLiUnionExtractVerified(t *testing.T) {
	srv := httptest.NewServer(vulnerableExtractApp(false, http.StatusCreated))
	defer srv.Close()
	if got := runUnionExtract(t, srv); got != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", got)
	}
}

// The search never leaks stored names -> canary not surfaced -> not_reproduced.
func TestSQLiUnionExtractNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/register" {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"products":[]}`))
	}))
	defer srv.Close()
	if got := runUnionExtract(t, srv); got != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", got)
	}
}

// The canary surfaces in the benign control too -> not attributable to the
// injection -> not_reproduced.
func TestSQLiUnionExtractLeaksInControlRejected(t *testing.T) {
	srv := httptest.NewServer(vulnerableExtractApp(true, http.StatusCreated))
	defer srv.Close()
	if got := runUnionExtract(t, srv); got != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (canary in control)", got)
	}
}

// The setup write fails (cannot plant the canary) -> inconclusive.
func TestSQLiUnionExtractSetupFailsInconclusive(t *testing.T) {
	srv := httptest.NewServer(vulnerableExtractApp(false, http.StatusConflict))
	defer srv.Close()
	if got := runUnionExtract(t, srv); got != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive (setup write failed)", got)
	}
}

// setup_resource without a {{nonce}} slot -> invalid (no canary to plant).
func TestSQLiUnionExtractMissingNonceInvalid(t *testing.T) {
	v, _ := validators.Lookup("sqli.union_extract")
	ev, _ := json.Marshal(map[string]any{
		"setup_resource": map[string]any{
			"method": "POST", "url": "http://app.example.com/api/auth/register",
			"body": `{"email":"static@example.test","full_name":"static"}`,
		},
		"base_request": map[string]string{"method": "GET", "url": "http://app.example.com/api/products/search?q=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "q"},
			"payloads": map[string]string{"control": "z", "extract": "z' UNION SELECT full_name FROM users-- -"},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_extract":        true,
		"expected_marker_absent_in_control": true,
	})
	job := validators.Job{
		Finding: evidence.Finding{FindingID: "t", Type: "sqli.union_extract", Evidence: ev, Proof: proof},
		Nonce:   extractNonce,
	}
	res, err := v.Validate(context.Background(), job, validators.Env{Clock: validators.WallClock{}})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (no {{nonce}} in setup)", res.Verdict)
	}
}
