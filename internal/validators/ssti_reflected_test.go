package validators_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func buildSSTIJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/?name=guest"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "name"},
			"payloads": map[string]string{
				"control": "nocapsec-{{ssti_marker}}-literal",
				"ssti":    "{{ {{ssti_marker}} }}",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_candidate":      true,
		"expected_marker_absent_in_control": true,
		"repetitions":                       2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-ssti-reflected",
			Type:      "ssti.reflected",
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

func sstiEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

var jinjaExpr = regexp.MustCompile(`\{\{\s*(\d+)\*(\d+)\s*\}\}`)

// jinjaHandler: Jinja2-style template sink.
// Evaluates {{ A*B }}; plain text verbatim.
func jinjaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if m := jinjaExpr.FindStringSubmatch(name); m != nil {
			a, _ := strconv.ParseInt(m[1], 10, 64)
			b, _ := strconv.ParseInt(m[2], 10, 64)
			name = jinjaExpr.ReplaceAllString(name, strconv.FormatInt(a*b, 10))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello " + name))
	})
}

func TestSSTIReflectedVerified(t *testing.T) {
	srv := httptest.NewServer(jinjaHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "ssti.reflected", buildSSTIJob(t, port), sstiEnv(t, srv))
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
}

// echo-only sink -> not_reproduced.
func TestSSTIReflectedReflectionDoesNotPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello " + r.URL.Query().Get("name")))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "ssti.reflected", buildSSTIJob(t, port), sstiEnv(t, srv))
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (reflection is not proof)", res.Verdict)
	}
}

// missing {{ssti_marker}} slot -> invalid.
func TestSSTIReflectedMissingMarkerInvalid(t *testing.T) {
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": "http://app.example.com/?name=guest"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "name"},
			"payloads": map[string]string{"control": "x", "ssti": "{{ 2*2 }}"},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_candidate":      true,
		"expected_marker_absent_in_control": true,
		"repetitions":                       2,
	})
	job := validators.Job{Finding: evidence.Finding{FindingID: "t", Type: "ssti.reflected", Evidence: ev, Proof: proof}}
	res := runValidate(t, "ssti.reflected", job, validators.Env{Clock: validators.WallClock{}})
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", res.Verdict)
	}
}
