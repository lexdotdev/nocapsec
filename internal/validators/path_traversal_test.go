package validators_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

const ptCanary = "ROOT:X:0:0:NOCAPSEC_LEAK"

func ptEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

// queryLFIHandler leaks on traversal.
func queryLFIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("file") == "../../../../etc/passwd" {
			_, _ = w.Write([]byte("file contents:\n" + ptCanary + "\n"))
			return
		}
		_, _ = w.Write([]byte("welcome to the download portal"))
	})
}

// buildPathTraversalJob creates an LFI job.
func buildPathTraversalJob(t *testing.T, port int, marker, candidate string) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/download?file=welcome.txt"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "file"},
			"payloads": map[string]string{
				"candidate": candidate,
				"control":   "welcome.txt",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker": marker,
		"repetitions":     2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-pt",
			Type:      "path_traversal.file_read",
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

func TestPathTraversalVerified(t *testing.T) {
	srv := httptest.NewServer(queryLFIHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, ok := validators.Lookup("path_traversal.file_read")
	if !ok {
		t.Fatal("validator not registered")
	}
	res, err := v.Validate(context.Background(), buildPathTraversalJob(t, port, ptCanary, "../../../../etc/passwd"), ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
}

// Engine-sent marker is rejected.
func TestPathTraversalReflectionGuard(t *testing.T) {
	srv := httptest.NewServer(queryLFIHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")
	// Candidate marker reaches the URL.
	res, err := v.Validate(context.Background(),
		buildPathTraversalJob(t, port, "NOCAPSEC_LEAK", "../../NOCAPSEC_LEAK"), ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (marker reflected in request)", res.Verdict)
	}
}

// Encoded marker still reflects.
func TestPathTraversalReflectionEncodedMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		// Echo the decoded file param — no traversal.
		_, _ = w.Write([]byte("file '" + r.URL.Query().Get("file") + "' not found"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")
	// marker has chars the query encoder escapes.
	const marker = "ZZ MARK/9:Q"
	// marker smuggled into the candidate payload.
	res, err := v.Validate(context.Background(),
		buildPathTraversalJob(t, port, marker, "../../../../etc/passwd#"+marker), ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict == verdict.Verified {
		t.Fatalf("verdict = verified: encoded-marker reflection cheat NOT blocked")
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (marker rides in the candidate payload)", res.Verdict)
	}
}

// Double-encoded marker is still rejected.
func TestPathTraversalReflectionDoubleEncoded(t *testing.T) {
	srv := httptest.NewServer(queryLFIHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")
	// "../%2552OOT" -> "../%52OOT" -> "../ROOT".
	res, err := v.Validate(context.Background(),
		buildPathTraversalJob(t, port, "ROOT", "../%2552OOT"), ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (double-encoded marker reflected)", res.Verdict)
	}
}

// Marker never surfaces -> not_reproduced.
func TestPathTraversalNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("404 not found"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")
	res, err := v.Validate(context.Background(), buildPathTraversalJob(t, port, ptCanary, "../../../../etc/passwd"), ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", res.Verdict)
	}
}

// Control leak means no contrast.
func TestPathTraversalControlAlsoLeaks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("every page contains " + ptCanary))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")
	res, err := v.Validate(context.Background(), buildPathTraversalJob(t, port, ptCanary, "../../../../etc/passwd"), ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (control also leaks)", res.Verdict)
	}
}

// url_token supports path traversal.
func TestPathTraversalURLTokenVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "canary") {
			_, _ = w.Write([]byte("leaked: " + ptCanary))
			return
		}
		_, _ = w.Write([]byte("benign language file"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/appearance/langs/{{path}}"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "url_token", "name": "path"},
			"payloads": map[string]string{
				"candidate": "../../../data/canary.json",
				"control":   "en_US.json",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{"expected_marker": ptCanary, "repetitions": 2})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-pt-urltoken",
			Type:      "path_traversal.file_read",
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

	v, _ := validators.Lookup("path_traversal.file_read")
	res, err := v.Validate(context.Background(), job, ptEnv(t, srv))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (url_token path segment)", res.Verdict)
	}
}

// Missing url_token is invalid.
func TestPathTraversalURLTokenAbsent(t *testing.T) {
	ps := strconv.Itoa(9) // never dialed; build fails first
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/appearance/langs/fixed.json"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "url_token", "name": "path"},
			"payloads": map[string]string{
				"candidate": "../../../data/canary.json",
				"control":   "en_US.json",
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{"expected_marker": ptCanary, "repetitions": 2})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-pt-urltoken-absent",
			Type:      "path_traversal.file_read",
			Evidence:  ev,
			Proof:     proof,
		},
	}

	v, _ := validators.Lookup("path_traversal.file_read")
	res, err := v.Validate(context.Background(), job, validators.Env{Clock: validators.WallClock{}})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (url token absent from base_request)", res.Verdict)
	}
}
