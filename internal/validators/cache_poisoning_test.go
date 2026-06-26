package validators_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

const canaryNonce = "deadbeefdeadbeefdeadbeefdeadbeef"

func cachePoisonJob(t *testing.T, port int, evidenceObj map[string]any) validators.Job {
	t.Helper()
	ev, _ := json.Marshal(evidenceObj)
	proof, _ := json.Marshal(map[string]any{
		"expected_canary_in_clean":          true,
		"expected_canary_absent_in_control": true,
		"repetitions":                       2,
	})
	base := "http://app.example.com:" + strconv.Itoa(port)
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-cache-poisoning",
			Type:      "cache_poisoning.canary",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: canaryNonce,
	}
}

// standardEvidence uses victim-shaped reads.
func standardEvidence(port int) map[string]any {
	base := "http://app.example.com:" + strconv.Itoa(port)
	return map[string]any{
		"poison_request": map[string]any{
			"method":  "GET",
			"url":     base + "/home?cb={{cachebuster}}",
			"headers": []map[string]string{{"name": "X-Forwarded-Host", "value": "{{canary}}.nocap.example"}},
		},
		"clean_request":   map[string]any{"method": "GET", "url": base + "/home?cb={{cachebuster}}"},
		"control_request": map[string]any{"method": "GET", "url": base + "/home?cb={{cachebuster}}"},
	}
}

func runCachePoison(t *testing.T, h http.Handler, ev func(port int) map[string]any) validators.Result {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, port := serverAddr(t, srv)
	v, ok := validators.Lookup("cache_poisoning.canary")
	if !ok {
		t.Fatal("validator not registered")
	}
	res, err := v.Validate(context.Background(), cachePoisonJob(t, port, ev(port)), sstiEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return res
}

// keyedCacheHandler simulates the vuln.
func keyedCacheHandler() http.Handler {
	var mu sync.Mutex
	cache := map[string]string{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cb := r.URL.Query().Get("cb")
		mu.Lock()
		body, hit := cache[cb]
		if !hit {
			body = "host=" + r.Header.Get("X-Forwarded-Host")
			cache[cb] = body
		}
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	})
}

func TestCachePoisoningVerified(t *testing.T) {
	res := runCachePoison(t, keyedCacheHandler(), standardEvidence)
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
}

// No shared cache: clean never sees the canary.
func TestCachePoisoningNotReproduced(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host=" + r.Header.Get("X-Forwarded-Host")))
	})
	res := runCachePoison(t, h, standardEvidence)
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", res.Verdict)
	}
}

// Global reflection is not proof.
func TestCachePoisoningControlLeakNotProof(t *testing.T) {
	var mu sync.Mutex
	var cached string
	var has bool
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if !has {
			cached, has = "host="+r.Header.Get("X-Forwarded-Host"), true
		}
		body := cached
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	})
	res := runCachePoison(t, h, standardEvidence)
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (control received the canary)", res.Verdict)
	}
}

// Poison precondition fails -> inconclusive.
func TestCachePoisoningPoisonErrorInconclusive(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	res := runCachePoison(t, h, standardEvidence)
	if res.Verdict != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", res.Verdict)
	}
}

// Missing canary is invalid.
func TestCachePoisoningMissingCanaryInvalid(t *testing.T) {
	base := "http://app.example.com/home?cb={{cachebuster}}"
	ev, _ := json.Marshal(map[string]any{
		"poison_request":  map[string]any{"method": "GET", "url": base},
		"clean_request":   map[string]any{"method": "GET", "url": base},
		"control_request": map[string]any{"method": "GET", "url": base},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_canary_in_clean": true, "expected_canary_absent_in_control": true, "repetitions": 2,
	})
	job := validators.Job{
		Finding: evidence.Finding{FindingID: "t", Type: "cache_poisoning.canary", Evidence: ev, Proof: proof},
		Nonce:   canaryNonce,
	}
	v, _ := validators.Lookup("cache_poisoning.canary")
	res, err := v.Validate(context.Background(), job, validators.Env{Clock: validators.WallClock{}})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", res.Verdict)
	}
}

// Clean must be victim-shaped.
func TestCachePoisoningCanaryInCleanInvalid(t *testing.T) {
	base := "http://app.example.com/home?cb={{cachebuster}}"
	ev, _ := json.Marshal(map[string]any{
		"poison_request": map[string]any{
			"method": "GET", "url": base,
			"headers": []map[string]string{{"name": "X-Forwarded-Host", "value": "{{canary}}.x"}},
		},
		"clean_request":   map[string]any{"method": "GET", "url": base + "&q={{canary}}"},
		"control_request": map[string]any{"method": "GET", "url": base},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_canary_in_clean": true, "expected_canary_absent_in_control": true, "repetitions": 2,
	})
	job := validators.Job{
		Finding: evidence.Finding{FindingID: "t", Type: "cache_poisoning.canary", Evidence: ev, Proof: proof},
		Nonce:   canaryNonce,
	}
	v, _ := validators.Lookup("cache_poisoning.canary")
	res, err := v.Validate(context.Background(), job, validators.Env{Clock: validators.WallClock{}})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (clean must not carry the canary)", res.Verdict)
	}
}
