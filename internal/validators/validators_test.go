package validators_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type fakeResolver struct {
	ips []net.IP
}

func (f fakeResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	return f.ips, nil
}

func serverAddr(t *testing.T, srv *httptest.Server) (net.IP, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	ip := net.ParseIP(host)
	port, _ := strconv.Atoi(portStr)
	return ip, port
}

func testEnforcer(t *testing.T, srv *httptest.Server) validators.PolicyEnforcer {
	t.Helper()
	ip, port := serverAddr(t, srv)
	resolver := fakeResolver{ips: []net.IP{ip}}
	p := policy.URLPolicy{
		AllowedSchemes:     []string{"http"},
		AllowedHosts:       []string{"app.example.com"},
		AllowedPorts:       []int{port},
		AllowRedirects:     true,
		MaxRedirects:       5,
		BlockLoopback:      false,
		BlockPrivateIPs:    false,
		InternalAssessment: true,
	}
	checker := policy.NewChecker(p, resolver)
	return &testPolicyEnforcer{checker: checker}
}

// testPolicyEnforcer satisfies validators.PolicyEnforcer for tests.
type testPolicyEnforcer struct {
	checker *policy.Checker
}

func (e *testPolicyEnforcer) CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error) {
	return e.checker.CheckURL(raw, phase)
}

func (e *testPolicyEnforcer) CheckRedirect(from, to string) error {
	return e.checker.CheckRedirect(from, to)
}

func (e *testPolicyEnforcer) HTTPClientFor(_ validators.Job) (*http.Client, error) {
	return &http.Client{}, nil
}

func (e *testPolicyEnforcer) BrowserProxyFor(_ validators.Job) (string, func(), error) {
	return "", nil, nil
}

func (e *testPolicyEnforcer) Checker() *policy.Checker { return e.checker }

func buildJob(t *testing.T, port int, marker string) validators.Job {
	t.Helper()
	portStr := strconv.Itoa(port)
	ev, _ := json.Marshal(map[string]any{
		"request":              map[string]string{"method": "GET", "url": "http://app.example.com:" + portStr + "/download?file=../../etc/passwd"},
		"vulnerable_parameter": "file",
		"expected_markers":     []string{marker},
		"negative_control":     map[string]string{"method": "GET", "url": "http://app.example.com:" + portStr + "/download?file=normal.txt"},
	})
	proof, _ := json.Marshal(map[string]bool{
		"require_marker":                  true,
		"require_negative_control_absent": true,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-pt",
			Type:      "path_traversal.file_read",
			Target: evidence.Target{
				ExpectedOrigin: "http://app.example.com:" + portStr,
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
	const marker = "CANARY_FILE_CONTENT"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("file") == "normal.txt" {
			_, _ = w.Write([]byte("normal content"))
			return
		}
		_, _ = w.Write([]byte("preamble " + marker + " epilogue"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := testEnforcer(t, srv)
	v, ok := validators.Lookup("path_traversal.file_read")
	if !ok {
		t.Fatal("validator not registered")
	}

	job := buildJob(t, port, marker)
	env := validators.Env{
		Policy:    pe,
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
	if len(res.Proof) == 0 {
		t.Fatal("verified outcome must carry a proof block")
	}
	if !bytes.Contains(res.Proof, []byte(marker)) {
		t.Fatalf("proof %s missing matched marker %q", res.Proof, marker)
	}
}

func TestPathTraversalNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("normal content"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := testEnforcer(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")

	job := buildJob(t, port, "ABSENT_MARKER")
	env := validators.Env{
		Policy:    pe,
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

// Marker in both candidate and control -> not_reproduced (not traversal).
func TestPathTraversalMarkerInBoth(t *testing.T) {
	const marker = "SHARED_CONTENT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("some " + marker + " data"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	pe := testEnforcer(t, srv)
	v, _ := validators.Lookup("path_traversal.file_read")

	job := buildJob(t, port, marker)
	env := validators.Env{
		Policy:    pe,
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}

	res, err := v.Validate(context.Background(), job, env)
	result := res.Verdict
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (marker in both)", result)
	}
}

// All registered validators have a Cap() that matches a known pool.
func TestAllValidatorsHaveCap(t *testing.T) {
	known := map[validators.Capability]bool{
		validators.CapHTTPReplay: true,
		validators.CapTiming:     true,
		validators.CapBrowser:    true,
		validators.CapOAST:       true,
	}
	for _, typ := range []string{
		"path_traversal.file_read", "xss.reflected", "xss.stored", "xss.blind",
		"open_redirect", "sqli.time_based", "sqli.boolean_based",
		"ssrf.oast", "xxe.oast", "command_injection.time_based",
		"command_injection.oast", "idor.read",
	} {
		v, ok := validators.Lookup(typ)
		if !ok {
			t.Errorf("type %q not registered", typ)
			continue
		}
		if !known[v.Cap()] {
			t.Errorf("type %q has unknown capability %q", typ, v.Cap())
		}
	}
}
