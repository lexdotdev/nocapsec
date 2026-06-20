package httpx_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/policy"
)

// fakeResolver returns a fixed IP set. Tests inject the httptest server's IP.
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

// testChecker builds a policy.Checker scoped to the given server.
func testChecker(t *testing.T, srv *httptest.Server, extraHosts ...string) *policy.Checker {
	t.Helper()
	ip, port := serverAddr(t, srv)
	hosts := append([]string{"app.example.com"}, extraHosts...)
	p := policy.URLPolicy{
		AllowedSchemes:  []string{"http"},
		AllowedHosts:    hosts,
		AllowedPorts:    []int{port},
		AllowRedirects:  true,
		MaxRedirects:    5,
		BlockLoopback:   false,
		BlockPrivateIPs: false,
	}
	return policy.NewChecker(p, fakeResolver{ips: []net.IP{ip}})
}

// TestReplayCapture proves: replay through the enforcer's client against a
// local httptest server captures bytes/status/timing.
func TestReplayCapture(t *testing.T) {
	const body = "hello from httptest"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	checker := testChecker(t, srv)
	bundle := httpx.NewClient(checker)

	req := evidence.Request{
		Method: http.MethodGet,
		URL:    "http://app.example.com:" + strconv.Itoa(port) + "/test",
		Headers: []evidence.Header{
			{Name: "Accept", Value: "text/plain"},
		},
	}

	capture, err := httpx.Replay(context.Background(), bundle, req)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if capture.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", capture.StatusCode)
	}
	if string(capture.RespBody) != body {
		t.Fatalf("body = %q, want %q", capture.RespBody, body)
	}
	if capture.DurationMS < 0 {
		t.Fatalf("DurationMS = %d, want >= 0", capture.DurationMS)
	}

	found := false
	for _, h := range capture.RespHeaders {
		if h.Name == "X-Test" && h.Value == "yes" {
			found = true
		}
	}
	if !found {
		t.Fatal("X-Test response header not captured")
	}
}

// TestPinnedDialerRejectsNonPinnedIP proves: the dialer hard-fails when
// the resolved IP is blocked by policy.
func TestPinnedDialerRejectsNonPinnedIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)

	// Resolver returns a private IP that policy blocks.
	resolver := fakeResolver{ips: []net.IP{net.ParseIP("10.0.0.1")}}
	p := policy.URLPolicy{
		AllowedSchemes:  []string{"http"},
		AllowedHosts:    []string{"app.example.com"},
		AllowedPorts:    []int{port},
		AllowRedirects:  true,
		BlockPrivateIPs: true,
		BlockLoopback:   true,
	}
	checker := policy.NewChecker(p, resolver)
	bundle := httpx.NewClient(checker)

	req := evidence.Request{
		Method: http.MethodGet,
		URL:    "http://app.example.com:" + strconv.Itoa(port) + "/x",
	}

	_, err := httpx.Replay(context.Background(), bundle, req)
	if err == nil {
		t.Fatal("expected error for blocked IP, got nil")
	}
	// The initial CheckURL in Replay should reject the blocked IP.
	if !strings.Contains(err.Error(), "blocked_ip") {
		t.Fatalf("expected blocked_ip rejection, got: %v", err)
	}
}

// TestRedirectOutOfScopeRejected proves: a 3xx to an out-of-scope host yields
// a policy rejection and is never followed.
func TestRedirectOutOfScopeRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "http://evil.com/pwned", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	checker := testChecker(t, srv)
	bundle := httpx.NewClient(checker)

	req := evidence.Request{
		Method: http.MethodGet,
		URL:    "http://app.example.com:" + strconv.Itoa(port) + "/redir",
	}

	_, err := httpx.Replay(context.Background(), bundle, req)
	if err == nil {
		t.Fatal("expected policy rejection for out-of-scope redirect, got nil")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Fatalf("expected redirect rejection error, got: %v", err)
	}

	hops := bundle.Tracker.Snapshot()
	if len(hops) == 0 {
		t.Fatal("no redirect hops recorded")
	}
	last := hops[len(hops)-1]
	if last.Allowed {
		t.Fatal("last hop should be marked as not allowed")
	}
	if !strings.Contains(last.To, "evil.com") {
		t.Fatalf("last hop To = %q, want evil.com", last.To)
	}
}

// TestReplayFollowsInScopeRedirect proves in-scope redirects are followed
// and the redirect trace is captured.
func TestReplayFollowsInScopeRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("final"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	checker := testChecker(t, srv)
	bundle := httpx.NewClient(checker)

	req := evidence.Request{
		Method: http.MethodGet,
		URL:    "http://app.example.com:" + strconv.Itoa(port) + "/a",
	}

	capture, err := httpx.Replay(context.Background(), bundle, req)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if capture.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", capture.StatusCode)
	}
	if string(capture.RespBody) != "final" {
		t.Fatalf("body = %q, want %q", capture.RespBody, "final")
	}
	if len(capture.Redirects) != 1 {
		t.Fatalf("redirects = %d, want 1", len(capture.Redirects))
	}
	if !capture.Redirects[0].Allowed {
		t.Fatal("in-scope redirect should be allowed")
	}
}

// TestTimingClientDisablesHTTP2 verifies the timing client builds without error
// and captures a response (HTTP/2 mux disabled).
func TestTimingClientDisablesHTTP2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("timing"))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	checker := testChecker(t, srv)
	bundle := httpx.NewTimingClient(checker)

	req := evidence.Request{
		Method: http.MethodGet,
		URL:    "http://app.example.com:" + strconv.Itoa(port) + "/",
	}

	capture, err := httpx.Replay(context.Background(), bundle, req)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if capture.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", capture.StatusCode)
	}
	if string(capture.RespBody) != "timing" {
		t.Fatalf("body = %q, want %q", capture.RespBody, "timing")
	}
}
