package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TestGracefulDrain_FinishInFlight ensures Close waits for in-flight jobs.
func TestGracefulDrain_FinishInFlight(t *testing.T) {
	const marker = "DRAIN_TEST_MARKER"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			_, _ = w.Write([]byte(marker))
			return
		}
		_, _ = w.Write([]byte("clean"))
	}))
	defer target.Close()

	ip, port := serverAddr(t, target)
	portStr := strconv.Itoa(port)
	resolver := fakeResolver{ips: []net.IP{ip}}

	e, err := New(Config{Resolver: resolver, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	finding := `{
  "finding_id": "drain-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["` + marker + `"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	// Submit concurrent jobs.
	var wg sync.WaitGroup
	results := make([]verdict.Report, 3)
	for i := range 3 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r, verErr := e.Verify(context.Background(), []byte(finding))
			if verErr != nil {
				t.Errorf("Verify[%d]: %v", idx, verErr)
				return
			}
			results[idx] = r
		}(i)
	}
	wg.Wait()

	// All should have completed before Close.
	for i, r := range results {
		if r.Verdict != verdict.Verified {
			t.Errorf("result[%d] = %q, want verified", i, r.Verdict)
		}
	}

	// Close should succeed (pools drained).
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestGracefulDrain_RejectsAfterClose ensures Verify returns ErrClosed after
// Close is called.
func TestGracefulDrain_RejectsAfterClose(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if closeErr := e.Close(); closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}

	_, err = e.Verify(context.Background(), []byte(`{"finding_id":"x","type":"path_traversal.file_read",
		"target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},
		"evidence":{"request":{"method":"GET","url":"https://a/x"},"vulnerable_parameter":"f",
		"expected_markers":["M"],"negative_control":{"method":"GET","url":"https://a/y"}},
		"proof":{"require_marker":true,"require_negative_control_absent":true}}`))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

// TestMetrics_CountsVerdictsAndPools confirms metrics track verdicts and pool
// dispatches.
func TestMetrics_CountsVerdictsAndPools(t *testing.T) {
	const marker = "METRICS_MARKER"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			_, _ = w.Write([]byte(marker))
			return
		}
		_, _ = w.Write([]byte("clean"))
	}))
	defer target.Close()

	ip, port := serverAddr(t, target)
	portStr := strconv.Itoa(port)
	resolver := fakeResolver{ips: []net.IP{ip}}

	e, err := New(Config{Resolver: resolver, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	finding := `{
  "finding_id": "m1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["` + marker + `"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	_, _ = e.Verify(context.Background(), []byte(finding))
	_, _ = e.Verify(context.Background(), []byte(`not json`))

	m := e.Metrics()
	if m.VerdictCount(verdict.Verified) != 1 {
		t.Fatalf("verified count = %d, want 1", m.VerdictCount(verdict.Verified))
	}
	if m.VerdictCount(verdict.Invalid) != 1 {
		t.Fatalf("invalid count = %d, want 1", m.VerdictCount(verdict.Invalid))
	}
	if m.PoolCount(CapHTTPReplay) != 1 {
		t.Fatalf("http-replay pool count = %d, want 1", m.PoolCount(CapHTTPReplay))
	}
}
