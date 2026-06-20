package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// fakeResolver returns a fixed IP for every lookup.
type fakeResolver struct {
	ips []net.IP
	err error
}

func (f fakeResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ips, nil
}

// publicResolver resolves to a public IP so policy doesn't block it.
func publicResolver() policy.Resolver {
	return fakeResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}
}

func TestDispatchRunsTaskOnItsPool(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer func() { _ = d.Close() }()

	ran := false
	err := d.Dispatch(context.Background(), Task{
		Capability: CapHTTPReplay,
		Target:     "app.example.com",
		Run:        func(context.Context) error { ran = true; return nil },
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !ran {
		t.Fatal("task did not run")
	}
}

func TestDispatchUnknownCapability(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer func() { _ = d.Close() }()

	err := d.Dispatch(context.Background(), Task{
		Capability: "nope",
		Target:     "app.example.com",
		Run:        func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

// A finding with no Run wired surfaces ErrNotImplemented.
func TestDispatchNilRunIsNotImplemented(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer func() { _ = d.Close() }()

	err := d.Dispatch(context.Background(), Task{Capability: CapOAST, Target: "t"})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v, want ErrNotImplemented", err)
	}
}

func TestDispatchEnforcesPerTargetLimit(t *testing.T) {
	d := newDispatcher(Limits{Browser: 2})
	defer func() { _ = d.Close() }()

	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Dispatch(context.Background(), Task{
				Capability: CapBrowser,
				Target:     "app.example.com",
				Run: func(context.Context) error {
					entered <- struct{}{}
					<-release
					return nil
				},
			})
		}()
	}

	<-entered
	<-entered
	select {
	case <-entered:
		t.Fatal("a third task entered; per-target limit not enforced")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	wg.Wait()
}

func TestPoolRecoversFromPanic(t *testing.T) {
	d := newDispatcher(Limits{HTTPReplay: 1})
	defer func() { _ = d.Close() }()

	err := d.Dispatch(context.Background(), Task{
		Capability: CapHTTPReplay,
		Target:     "t",
		Run:        func(context.Context) error { panic("boom") },
	})
	if err == nil {
		t.Fatal("expected error from panicking task")
	}

	ran := false
	err = d.Dispatch(context.Background(), Task{
		Capability: CapHTTPReplay,
		Target:     "t",
		Run:        func(context.Context) error { ran = true; return nil },
	})
	if err != nil {
		t.Fatalf("dispatch after panic: %v", err)
	}
	if !ran {
		t.Fatal("pool stopped serving after a panic")
	}
}

func TestDispatchHonorsContextCancellation(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer func() { _ = d.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := d.Dispatch(ctx, Task{
		Capability: CapHTTPReplay,
		Target:     "t",
		Run:        func(context.Context) error { return nil },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestJobStorePutGet(t *testing.T) {
	s := newJobStore()
	if _, ok := s.get("missing"); ok {
		t.Fatal("empty store returned a job")
	}

	want := verdict.NewReport("f1", "xss_reflected", verdict.Inconclusive)
	s.put("f1", want)
	got, ok := s.get("f1")
	if !ok || got.FindingID != "f1" {
		t.Fatalf("get = %+v, %v", got, ok)
	}
}

// malformed JSON -> invalid synchronously.
func TestEngineVerifyMalformedJSON(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, err := e.Verify(context.Background(), []byte(`not json`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", report.Verdict)
	}
}

// Unknown type -> invalid (no_validator).
func TestEngineVerifyUnknownType(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, err := e.Verify(context.Background(), []byte(`{"finding_id":"u1","type":"magic.vuln",
		"target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},
		"evidence":{"x":1},"proof":{}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", report.Verdict)
	}
}

// Out-of-scope host in evidence -> rejected.
func TestEngineVerifyPolicyRejected(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	// Evidence URL points at evil.com but target only allows app.example.com.
	finding := `{
  "finding_id": "rej-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"],
    "allowed_ports": [443]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://evil.com/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`
	report, err := e.Verify(context.Background(), []byte(finding))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verdict != verdict.Rejected {
		t.Fatalf("verdict = %q, want rejected", report.Verdict)
	}
}

// POST /verify with malformed JSON -> 422.
func TestHandlerPostVerifyInvalid(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	srv := httptest.NewServer(e.Handler())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/verify", "application/json", strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["verdict"] != "invalid" {
		t.Fatalf("verdict = %q, want invalid", body["verdict"])
	}
}

// POST /verify with valid finding -> 202 accepted with job_id;
// the background pipeline runs against a local httptest server.
func TestHandlerPostVerifyAccepted(t *testing.T) {
	// Stand up a target so the background pipeline completes.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	ip, port := serverAddr(t, target)
	portStr := strconv.Itoa(port)
	resolver := fakeResolver{ips: []net.IP{ip}}

	finding := `{
  "finding_id": "api-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	e, err := New(Config{Resolver: resolver, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv := httptest.NewServer(e.Handler())

	resp, err := http.Post(srv.URL+"/verify", "application/json", strings.NewReader(finding))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 202; body: %s", resp.StatusCode, body)
	}

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["job_id"] == "" {
		t.Fatal("missing job_id")
	}
	if body["status"] != "accepted" {
		t.Fatalf("status = %q, want accepted", body["status"])
	}

	// Wait for the background pipeline to settle.
	jobID := body["job_id"]
	deadline := time.After(3 * time.Second)
	for {
		r, ok := e.jobs.get(jobID)
		if ok && r.Verdict != "running" {
			break
		}
		select {
		case <-deadline:
			t.Fatal("pipeline did not settle")
		case <-time.After(10 * time.Millisecond):
		}
	}

	srv.Close()
	_ = e.Close()
}

// GET /verify/unknown -> 404.
func TestHandlerGetVerifyNotFound(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	srv := httptest.NewServer(e.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/verify/unknown-id")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// GET /verify/{id}/artifacts for unknown job -> 404.
func TestHandlerGetArtifactsNotFound(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	srv := httptest.NewServer(e.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/verify/unknown-id/artifacts")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// Full pipeline: path traversal verified (marker in candidate, absent in control).
func TestEngineVerifyPathTraversalVerified(t *testing.T) {
	const marker = "CANARY_MARKER_FILE"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("some content " + marker + " more content"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("normal file content"))
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	resolver := fakeResolver{ips: []net.IP{ip}}
	portStr := strconv.Itoa(port)

	finding := `{
  "finding_id": "pt-verified",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "auth": {"required": false},
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["` + marker + `"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	e, err := New(Config{Resolver: resolver, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, err := e.Verify(context.Background(), []byte(finding))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", report.Verdict)
	}
	if report.DecidedAt.IsZero() {
		t.Fatal("DecidedAt not stamped")
	}
}

// Full pipeline: path traversal not_reproduced (marker absent from candidate).
func TestEngineVerifyPathTraversalNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("normal file content"))
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	resolver := fakeResolver{ips: []net.IP{ip}}
	portStr := strconv.Itoa(port)

	finding := `{
  "finding_id": "pt-norepro",
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
    "expected_markers": ["CANARY_ABSENT"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	e, err := New(Config{Resolver: resolver, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, err := e.Verify(context.Background(), []byte(finding))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if report.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", report.Verdict)
	}
}

// serverAddr extracts IP and port from an httptest server.
func serverAddr(t *testing.T, srv *httptest.Server) (net.IP, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("parse IP %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return ip, port
}

// Ensure DecidedAt is stamped for all verdict types.
func TestEngineVerifyStampsDecidedAt(t *testing.T) {
	e, err := New(Config{Resolver: publicResolver()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	// Invalid finding.
	r, err := e.Verify(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.DecidedAt.IsZero() {
		t.Fatal("DecidedAt not stamped for invalid")
	}
}

// ValidatorCap matches engine pool.
func TestValidatorCapMatchesPool(t *testing.T) {
	v, ok := validators.Lookup("path_traversal.file_read")
	if !ok {
		t.Fatal("path_traversal.file_read not registered")
	}
	if v.Cap() != CapHTTPReplay {
		t.Fatalf("cap = %q, want http-replay", v.Cap())
	}
}

// Every job persists redacted evidence, policy snapshot, and HTTP exchange.
func TestEngineVerifyPersistsRedactedArtifacts(t *testing.T) {
	const marker = "CANARY_FILE_CONTENT"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			_, _ = w.Write([]byte(marker))
			return
		}
		_, _ = w.Write([]byte("normal"))
	}))
	defer srv.Close()

	ip, port := serverAddr(t, srv)
	resolver := fakeResolver{ips: []net.IP{ip}}
	portStr := strconv.Itoa(port)
	store := artifacts.NewStore()

	finding := `{
  "finding_id": "art-1",
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

	e, err := New(Config{Resolver: resolver, Store: store, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, err := e.Verify(context.Background(), []byte(finding))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Must have all three artifact refs.
	for _, key := range []string{"evidence", "policy", "http_exchange"} {
		ref, ok := report.Artifacts[key]
		if !ok {
			t.Fatalf("missing artifact ref %q", key)
		}
		data, getErr := store.Get(context.Background(), ref)
		if getErr != nil {
			t.Fatalf("Get(%q): %v", ref, getErr)
		}
		if len(data) == 0 {
			t.Fatalf("artifact %q is empty", key)
		}
	}

	// Verify redaction works end-to-end: put data with a Cookie header
	// through the store and confirm the credential is stripped.
	ref, err := store.Put(context.Background(), "redact-test", artifacts.KindHTTPExchange,
		[]byte("Cookie: session=secret\nContent-Type: text/html"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Contains(string(data), "session=secret") {
		t.Fatal("credential not redacted in stored artifact")
	}
}

// Expired auth state -> inconclusive, not false negative.
func TestEngineVerifyExpiredAuthYieldsInconclusive(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	clock := &fixedClock{now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	authStore, err := authstate.NewStore(key, clock)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	// Store an already-expired auth state.
	state := &authstate.AuthState{
		ID:             "as-expired",
		AllowedOrigins: []string{"https://app.example.com"},
		ExpiresAt:      time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	if putErr := authStore.Put(context.Background(), state, &authstate.Credentials{}); putErr != nil {
		t.Fatalf("Put: %v", putErr)
	}

	finding := `{
  "finding_id": "auth-exp-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "auth": {"required": true, "auth_state_id": "as-expired"},
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	e, err := New(Config{
		Resolver:  publicResolver(),
		AuthStore: authStore,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, verErr := e.Verify(context.Background(), []byte(finding))
	if verErr != nil {
		t.Fatalf("Verify: %v", verErr)
	}
	if report.Verdict != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", report.Verdict)
	}
	if report.Reason != "auth_expired" {
		t.Fatalf("reason = %q, want auth_expired", report.Reason)
	}
}

// Missing auth state -> inconclusive.
func TestEngineVerifyMissingAuthYieldsInconclusive(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	authStore, err := authstate.NewStore(key, nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	finding := `{
  "finding_id": "auth-miss-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "auth": {"required": true, "auth_state_id": "nonexistent"},
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	e, err := New(Config{
		Resolver:  publicResolver(),
		AuthStore: authStore,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, verErr := e.Verify(context.Background(), []byte(finding))
	if verErr != nil {
		t.Fatalf("Verify: %v", verErr)
	}
	if report.Verdict != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", report.Verdict)
	}
	if report.Reason != "auth_not_found" {
		t.Fatalf("reason = %q, want auth_not_found", report.Reason)
	}
}

// fixedClock implements both validators.Clock and authstate.Clock.
type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time                  { return c.now }
func (c *fixedClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }
