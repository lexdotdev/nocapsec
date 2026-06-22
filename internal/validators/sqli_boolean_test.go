package validators_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func buildBooleanJob(t *testing.T, port int) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item?id=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "id"},
			"payloads": map[string]string{
				"baseline":        "1",
				"true_condition":  "1 AND 1=1",
				"false_condition": "1 AND 1=0",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_true_similarity_to_baseline": true,
		"expected_false_difference":            true,
		"compare":                              []string{"status", "body_hash_fuzzy", "content_length_bucket"},
		"repetitions":                          2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-sqli-bool",
			Type:      "sqli.boolean_based",
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

func booleanEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

// booleanSQLiHandler models true/false arms.
func booleanSQLiHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch id {
		case "1", "1 AND 1=1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>Product</title><p>Widget A - $19.99</p></html>`))
		case "1 AND 1=0":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>No Results</title><p>No products found.</p></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestSQLiBooleanVerified(t *testing.T) {
	srv := httptest.NewServer(booleanSQLiHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, ok := validators.Lookup("sqli.boolean_based")
	if !ok {
		t.Fatal("validator not registered")
	}

	job := buildBooleanJob(t, port)
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

// No false difference is not_reproduced.
func TestSQLiBooleanNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>Product</title><p>Widget A</p></html>`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.boolean_based")
	job := buildBooleanJob(t, port)
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

// True must resemble baseline.
func TestSQLiBooleanTrueDiffersFromBaseline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		// Every request returns something different.
		switch id {
		case "1":
			_, _ = w.Write([]byte("baseline page"))
		case "1 AND 1=1":
			_, _ = w.Write([]byte("true page differs"))
		case "1 AND 1=0":
			_, _ = w.Write([]byte("false page"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.boolean_based")
	job := buildBooleanJob(t, port)
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (true differs from baseline)", result)
	}
}

// Status difference can verify.
func TestSQLiBooleanStatusCodeDiff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch id {
		case "1", "1 AND 1=1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		case "1 AND 1=0":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("error"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item?id=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "id"},
			"payloads": map[string]string{
				"baseline":        "1",
				"true_condition":  "1 AND 1=1",
				"false_condition": "1 AND 1=0",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_true_similarity_to_baseline": true,
		"expected_false_difference":            true,
		"compare":                              []string{"status"},
		"repetitions":                          2,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-status-diff",
			Type:      "sqli.boolean_based",
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

	v, _ := validators.Lookup("sqli.boolean_based")
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

// Bad evidence JSON -> invalid.
func TestSQLiBooleanInvalidEvidence(t *testing.T) {
	v, _ := validators.Lookup("sqli.boolean_based")
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-invalid",
			Type:      "sqli.boolean_based",
			Evidence:  json.RawMessage(`{"not": "valid"}`),
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

// Dynamic content is masked.
func TestSQLiBooleanDynamicContentMasked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		switch id {
		case "1", "1 AND 1=1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<p>Product A</p><span>req-550e8400-e29b-41d4-a716-446655440000</span>`))
		case "1 AND 1=0":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<p>No results</p><span>req-6ba7b810-9dad-11d1-80b4-00c04fd430c8</span>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("sqli.boolean_based")
	job := buildBooleanJob(t, port)
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (dynamic tokens masked)", result)
	}
}

// Slot must exist in base request.
func TestSQLiBooleanInjectionLocationAbsent(t *testing.T) {
	srv := httptest.NewServer(booleanSQLiHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	// Base request lacks the slot.
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "id"},
			"payloads": map[string]string{
				"baseline":        "1",
				"true_condition":  "1 AND 1=1",
				"false_condition": "1 AND 1=0",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_true_similarity_to_baseline": true,
		"expected_false_difference":            true,
		"compare":                              []string{"status", "body_hash_fuzzy"},
		"repetitions":                          2,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-loc-absent",
			Type:      "sqli.boolean_based",
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

	v, _ := validators.Lookup("sqli.boolean_based")
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (injection location absent from base_request)", res.Verdict)
	}
}

// Compare floor includes body hash.
func TestSQLiBooleanCompareFloor(t *testing.T) {
	// Only the body differs.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("id") == "1 AND 1=0" {
			_, _ = w.Write([]byte(`<html><title>No Results</title><p>No products found.</p></html>`))
			return
		}
		_, _ = w.Write([]byte(`<html><title>Product</title><p>Widget A - $19.99</p></html>`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/item?id=1"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "id"},
			"payloads": map[string]string{
				"baseline":        "1",
				"true_condition":  "1 AND 1=1",
				"false_condition": "1 AND 1=0",
			},
		},
	})
	// Floor still detects body changes.
	proof, _ := json.Marshal(map[string]any{
		"expected_true_similarity_to_baseline": true,
		"expected_false_difference":            true,
		"compare":                              []string{"status"},
		"repetitions":                          2,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-compare-floor",
			Type:      "sqli.boolean_based",
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

	v, _ := validators.Lookup("sqli.boolean_based")
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (floor forces body_hash_fuzzy)", res.Verdict)
	}
}

// Header injection works for SQLi.
func TestSQLiBooleanHeaderSlotVerified(t *testing.T) {
	// Header value drives the oracle.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		search := r.Header.Get("X-Search")
		switch search {
		case "widget", "widget' OR '1'='1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>Product</title><p>Widget A - $19.99</p></html>`))
		case "widget' OR '1'='2":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>No Results</title><p>No products found.</p></html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]any{
			"method": "GET",
			"url":    base + "/search",
			"headers": []map[string]string{
				{"name": "X-Search", "value": "widget"},
			},
		},
		"injection": map[string]any{
			"location": map[string]string{"kind": "header", "name": "X-Search"},
			"payloads": map[string]string{
				"baseline":        "widget",
				"true_condition":  "widget' OR '1'='1",
				"false_condition": "widget' OR '1'='2",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_true_similarity_to_baseline": true,
		"expected_false_difference":            true,
		"compare":                              []string{"status", "body_hash_fuzzy"},
		"repetitions":                          2,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-sqli-bool-header",
			Type:      "sqli.boolean_based",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "header-nonce",
	}

	v, ok := validators.Lookup("sqli.boolean_based")
	if !ok {
		t.Fatal("validator not registered")
	}
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (header slot)", res.Verdict)
	}
}

// CR/LF header value is rejected.
func TestSQLiBooleanHeaderCRLFRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]any{
			"method": "GET",
			"url":    base + "/search",
			"headers": []map[string]string{
				{"name": "X-Search", "value": "widget"},
			},
		},
		"injection": map[string]any{
			"location": map[string]string{"kind": "header", "name": "X-Search"},
			"payloads": map[string]string{
				"baseline":        "widget",
				"true_condition":  "widget' OR '1'='1\r\nInjected: evil",
				"false_condition": "widget' OR '1'='2",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_true_similarity_to_baseline": true,
		"expected_false_difference":            true,
		"compare":                              []string{"status", "body_hash_fuzzy"},
		"repetitions":                          2,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-sqli-bool-crlf",
			Type:      "sqli.boolean_based",
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

	v, ok := validators.Lookup("sqli.boolean_based")
	if !ok {
		t.Fatal("validator not registered")
	}
	env := booleanEnv(t, srv)

	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// CR/LF payload is invalid.
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (CRLF in header payload)", res.Verdict)
	}
}
