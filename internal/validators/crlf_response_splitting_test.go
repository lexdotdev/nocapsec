package validators_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

const crlfNonce = "a1b2c3d4e5f6a1b2"

func buildCRLFJob(t *testing.T, port int, split string) validators.Job {
	t.Helper()
	base := "http://app.example.com:" + strconv.Itoa(port)
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]string{"method": "GET", "url": base + "/set-lang?lang=en"},
		"injection": map[string]any{
			"location": map[string]string{"kind": "query", "name": "lang"},
			"payloads": map[string]string{"control": "en", "split": split},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_split_header_in_candidate":      true,
		"expected_split_header_absent_in_control": true,
		"repetitions": 2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-crlf",
			Type:      "crlf.response_splitting",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: crlfNonce,
	}
}

// rawReflect simulates raw header reflection.
func rawReflect(t *testing.T, w http.ResponseWriter, value string, fold bool) {
	t.Helper()
	if fold {
		value = strings.ReplaceAll(value, "\r\n", " ")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("response writer is not a Hijacker")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test
	body := "ok"
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nX-Lang: " + value + "\r\nConnection: close\r\n\r\n" + body
	_, _ = bufrw.WriteString(resp)
	_ = bufrw.Flush()
}

func runCRLF(t *testing.T, h http.Handler, split string) validators.Result {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	_, port := serverAddr(t, srv)
	res := runValidate(t, "crlf.response_splitting", buildCRLFJob(t, port, split), sstiEnv(t, srv))
	return res
}

// Injected param creates a header.
func TestCRLFResponseSplittingVerified(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawReflect(t, w, r.URL.Query().Get("lang"), false)
	})
	res := runCRLF(t, h, "en\r\nX-Nocap-Split-{{nonce}}: 1")
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
	if !strings.Contains(strings.ToLower(string(res.Proof)), crlfNonce) {
		t.Errorf("proof missing injected header nonce: %s", res.Proof)
	}
}

// Body reflection is not proof.
func TestCRLFResponseSplittingBodyReflectionNotProof(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("lang=" + r.URL.Query().Get("lang")))
	})
	res := runCRLF(t, h, "en\r\nX-Nocap-Split-{{nonce}}: 1")
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (body reflection is not a split)", res.Verdict)
	}
}

// Folded CR LF is not proof.
func TestCRLFResponseSplittingFoldingNotProof(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawReflect(t, w, r.URL.Query().Get("lang"), true)
	})
	res := runCRLF(t, h, "en\r\nX-Nocap-Split-{{nonce}}: 1")
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (folding is not a split)", res.Verdict)
	}
}

// Missing nonce is invalid.
func TestCRLFResponseSplittingMissingNonceInvalid(t *testing.T) {
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	res := runCRLF(t, h, "en\r\nX-Static-Header: 1")
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", res.Verdict)
	}
}

// Header slots reject CRLF.
func TestCRLFResponseSplittingHeaderSlotInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, port := serverAddr(t, srv)
	base := "http://app.example.com:" + strconv.Itoa(port)
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]any{
			"method":  "GET",
			"url":     base + "/",
			"headers": []map[string]string{{"name": "X-Lang", "value": "en"}},
		},
		"injection": map[string]any{
			"location": map[string]string{"kind": "header", "name": "X-Lang"},
			"payloads": map[string]string{"control": "en", "split": "en\r\nX-Nocap-Split-{{nonce}}: 1"},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_split_header_in_candidate":      true,
		"expected_split_header_absent_in_control": true,
		"repetitions": 2,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "t", Type: "crlf.response_splitting",
			Target: evidence.Target{
				ExpectedOrigin: base, AllowedHosts: []string{"app.example.com"},
				AllowedSchemes: []string{"http"}, AllowedPorts: []int{port},
			},
			Evidence: ev, Proof: proof,
		},
		Nonce: crlfNonce,
	}
	res := runValidate(t, "crlf.response_splitting", job, sstiEnv(t, srv))
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (header slot rejects CRLF)", res.Verdict)
	}
}

// Later instability is inconclusive.
func TestCRLFResponseSplittingUnstableInconclusive(t *testing.T) {
	var candHits atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("lang")
		fold := false
		if strings.Contains(val, "X-Nocap-Split") { // candidate arm
			fold = candHits.Add(1) > 1 // split once, then fold
		}
		rawReflect(t, w, val, fold)
	})
	res := runCRLF(t, h, "en\r\nX-Nocap-Split-{{nonce}}: 1")
	if res.Verdict != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive (unstable signal)", res.Verdict)
	}
}
