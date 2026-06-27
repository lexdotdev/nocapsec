package validators_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func buildStoredSSTIJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"setup_request": map[string]any{
			"method":  "POST",
			"url":     base + "/admin/product",
			"headers": []map[string]string{{"name": "content-type", "value": "application/x-www-form-urlencoded"}},
			"body":    "email_template=placeholder",
		},
		"injection": map[string]any{
			"location": map[string]string{"kind": "form", "name": "email_template"},
			"payloads": map[string]string{
				"control": "nocapsec-{{ssti_marker}}-literal",
				"ssti":    "{{ {{ssti_marker}} }}",
			},
		},
		"trigger": []map[string]string{{"method": "POST", "url": base + "/admin/service/activate"}},
		"observe": map[string]string{"method": "GET", "url": base + "/admin/email-log/latest"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_candidate":      true,
		"expected_marker_absent_in_control": true,
		"repetitions":                       2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-ssti-stored",
			Type:      "ssti.stored",
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

func storedSSTIEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

func storedSSTIApp(renderTemplates bool, setupStatus int) http.Handler {
	var mu sync.Mutex
	var template string
	var latestEmail string
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/product", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		vals, _ := url.ParseQuery(string(body))
		mu.Lock()
		template = vals.Get("email_template")
		mu.Unlock()
		w.WriteHeader(setupStatus)
	})
	mux.HandleFunc("/admin/service/activate", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		latestEmail = template
		if renderTemplates {
			latestEmail = jinjaExpr.ReplaceAllStringFunc(template, func(expr string) string {
				m := jinjaExpr.FindStringSubmatch(expr)
				a, _ := strconv.ParseInt(m[1], 10, 64)
				b, _ := strconv.ParseInt(m[2], 10, 64)
				return strconv.FormatInt(a*b, 10)
			})
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/admin/email-log/latest", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(latestEmail))
	})
	return mux
}

func runStoredSSTI(t *testing.T, h http.Handler) verdict.Verdict {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, port := serverAddr(t, srv)
	res := runValidate(t, "ssti.stored", buildStoredSSTIJob(t, port), storedSSTIEnv(t, srv))
	return res.Verdict
}

func TestSSTIStoredVerified(t *testing.T) {
	if got := runStoredSSTI(t, storedSSTIApp(true, http.StatusOK)); got != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", got)
	}
}

func TestSSTIStoredReflectionDoesNotPass(t *testing.T) {
	if got := runStoredSSTI(t, storedSSTIApp(false, http.StatusOK)); got != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", got)
	}
}

func TestSSTIStoredSetupFailureInconclusive(t *testing.T) {
	if got := runStoredSSTI(t, storedSSTIApp(true, http.StatusForbidden)); got != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", got)
	}
}

func TestSSTIStoredMissingMarkerInvalid(t *testing.T) {
	ev, _ := json.Marshal(map[string]any{
		"setup_request": map[string]any{
			"method": "POST", "url": "http://app.example.com/admin/product", "body": "email_template=placeholder",
		},
		"injection": map[string]any{
			"location": map[string]string{"kind": "form", "name": "email_template"},
			"payloads": map[string]string{"control": "x", "ssti": "{{ 2*2 }}"},
		},
		"trigger": []map[string]string{{"method": "POST", "url": "http://app.example.com/admin/service/activate"}},
		"observe": map[string]string{"method": "GET", "url": "http://app.example.com/admin/email-log/latest"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_candidate":      true,
		"expected_marker_absent_in_control": true,
		"repetitions":                       2,
	})
	job := validators.Job{Finding: evidence.Finding{FindingID: "t", Type: "ssti.stored", Evidence: ev, Proof: proof}}
	res := runValidate(t, "ssti.stored", job, validators.Env{Clock: validators.WallClock{}})
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", res.Verdict)
	}
}
