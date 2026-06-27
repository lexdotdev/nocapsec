package validators_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"sync"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func buildInbandJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/products/search?q=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "q"},
			"payloads": map[string]string{
				"control": "nomatch_zzz",
				"inband":  "nomatch_zzz' UNION SELECT {{sqli_marker}},2,3,4,5,6,7-- -",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_inband":         true,
		"expected_marker_absent_in_control": true,
		"repetitions":                       2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-sqli-inband",
			Type:      "sqli.inband",
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

func inbandEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

var arithExpr = regexp.MustCompile(`(\d+)\*(\d+)`)

// inbandSQLiHandler computes A*B.
// Benign requests return no products.
func inbandSQLiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if m := arithExpr.FindStringSubmatch(q); m != nil {
			a, _ := strconv.ParseInt(m[1], 10, 64)
			b, _ := strconv.ParseInt(m[2], 10, 64)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"products":[{"id":` + strconv.FormatInt(a*b, 10) + `,"name":"x"}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"products":[]}`))
	})
}

func TestSQLiInbandVerified(t *testing.T) {
	srv := httptest.NewServer(inbandSQLiHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "sqli.inband", buildInbandJob(t, port), inbandEnv(t, srv))
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
}

// Safe endpoint is not_reproduced.
// (no in-band read channel).
func TestSQLiInbandNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"products":[]}`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "sqli.inband", buildInbandJob(t, port), inbandEnv(t, srv))
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", res.Verdict)
	}
}

// Operand echo cannot fake product.
func TestSQLiInbandReflectionDoesNotPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Echo operands, never product.
		_, _ = w.Write([]byte(`{"echo":"` + r.URL.Query().Get("q") + `"}`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "sqli.inband", buildInbandJob(t, port), inbandEnv(t, srv))
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (reflection is not proof)", res.Verdict)
	}
}

// Control product breaks attribution.
func TestSQLiInbandPresentInControlRejected(t *testing.T) {
	var mu sync.Mutex
	var last string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		if m := arithExpr.FindStringSubmatch(q); m != nil {
			a, _ := strconv.ParseInt(m[1], 10, 64)
			b, _ := strconv.ParseInt(m[2], 10, 64)
			last = strconv.FormatInt(a*b, 10)
			_, _ = w.Write([]byte(`{"products":[{"id":` + last + `}]}`))
			return
		}
		// Control echoes the last product.
		_, _ = w.Write([]byte(`{"products":[{"id":` + last + `}]}`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "sqli.inband", buildInbandJob(t, port), inbandEnv(t, srv))
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (marker present in control)", res.Verdict)
	}
}

// Missing sqli_marker is invalid.
func TestSQLiInbandMissingMarkerInvalid(t *testing.T) {
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": "http://app.example.com/products/search?q=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "q"},
			"payloads": map[string]string{"control": "x", "inband": "no marker here"},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker_in_inband":         true,
		"expected_marker_absent_in_control": true,
		"repetitions":                       2,
	})
	job := validators.Job{Finding: evidence.Finding{FindingID: "t", Type: "sqli.inband", Evidence: ev, Proof: proof}}
	res := runValidate(t, "sqli.inband", job, validators.Env{Clock: validators.WallClock{}})
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", res.Verdict)
	}
}
