package validators_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
)

type fakeResolver struct {
	ips []net.IP
}

func (f fakeResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	return f.ips, nil
}

// runValidate fails on lookup/runtime errors.
func runValidate(t *testing.T, typ string, job validators.Job, env validators.Env) validators.Result {
	t.Helper()
	v, ok := validators.Lookup(typ)
	if !ok {
		t.Fatalf("validator %q not registered", typ)
	}
	res, err := v.Validate(context.Background(), job, env)
	if err != nil {
		t.Fatalf("Validate(%s): %v", typ, err)
	}
	return res
}

func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func appOrigin(port int) string { return fmt.Sprintf("http://app.example.com:%d", port) }

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

// testPolicyEnforcer wraps policy.
type testPolicyEnforcer struct {
	checker       *policy.Checker
	proxyURL      string
	cleanupCalled *bool
}

func (e *testPolicyEnforcer) CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error) {
	return e.checker.CheckURL(raw, phase)
}

func (e *testPolicyEnforcer) CheckRedirect(from, to string) error {
	return e.checker.CheckRedirect(from, to)
}

func (e *testPolicyEnforcer) BrowserProxyFor(_ validators.Job) (string, func(), error) {
	var cleanup func()
	if e.cleanupCalled != nil {
		cleanup = func() { *e.cleanupCalled = true }
	}
	return e.proxyURL, cleanup, nil
}

func (e *testPolicyEnforcer) Checker() *policy.Checker { return e.checker }

// Validator caps match known pools.
func TestAllValidatorsHaveCap(t *testing.T) {
	registry, err := validators.DefaultRegistry()
	if err != nil {
		t.Fatalf("default registry: %v", err)
	}
	known := map[validators.Capability]bool{
		validators.CapHTTPReplay: true,
		validators.CapTiming:     true,
		validators.CapBrowser:    true,
		validators.CapOAST:       true,
	}
	for _, typ := range []string{
		"path_traversal.file_read", "xss.reflected", "xss.stored", "xss.blind",
		"open_redirect", "sqli.time_based", "sqli.boolean_based",
		"sqli.inband", "sqli.union_extract", "nosqli.auth_bypass",
		"ssti.reflected", "ssti.stored", "crlf.response_splitting",
		"cache_poisoning.canary", "ssrf.oast", "xxe.oast",
		"command_injection.time_based", "command_injection.oast",
		"idor.read",
	} {
		v, ok := registry.Lookup(typ)
		if !ok {
			t.Errorf("type %q not registered", typ)
			continue
		}
		if !known[v.Cap()] {
			t.Errorf("type %q has unknown capability %q", typ, v.Cap())
		}
	}
}

func TestRegistryRejectsDuplicateTypes(t *testing.T) {
	_, err := validators.NewRegistry(stubValidator{typ: "x"}, stubValidator{typ: "x"})
	if err == nil {
		t.Fatal("expected duplicate type error")
	}
}

type stubValidator struct {
	typ string
}

func (v stubValidator) Type() string { return v.typ }

func (stubValidator) Cap() validators.Capability { return validators.CapHTTPReplay }

func (stubValidator) Validate(context.Context, validators.Job, validators.Env) (validators.Result, error) {
	return validators.Result{}, nil
}
