package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync"

	"github.com/lexdotdev/nocapsec/internal/policy"
)

// RedirectTracker records hops.
type RedirectTracker struct {
	mu   sync.Mutex
	hops []RedirectHop
}

// Snapshot copies recorded hops.
func (rt *RedirectTracker) Snapshot() []RedirectHop {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]RedirectHop, len(rt.hops))
	copy(out, rt.hops)
	return out
}

// Reset clears hops for reuse across requests.
func (rt *RedirectTracker) Reset() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.hops = rt.hops[:0]
}

// PinnedSet is the dial allowlist.
type PinnedSet struct {
	mu  sync.Mutex
	ips []net.IP
}

// Set replaces pinned IPs; call per request.
func (p *PinnedSet) Set(ips []net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ips = make([]net.IP, len(ips))
	copy(p.ips, ips)
}

// Add appends resolved IPs (per redirect hop).
func (p *PinnedSet) Add(ips []net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ips = append(p.ips, ips...)
}

func (p *PinnedSet) contains(ip net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pinned := range p.ips {
		if pinned.Equal(ip) {
			return true
		}
	}
	return false
}

// ClientBundle wires replay state.
type ClientBundle struct {
	Client  *http.Client
	Pinned  *PinnedSet
	Tracker *RedirectTracker
	Checker *policy.Checker
}

// newBundle wires a transport bundle.
func newBundle(c *policy.Checker, transport *http.Transport) *ClientBundle {
	jar, _ := cookiejar.New(nil)
	pinned := &PinnedSet{}
	tracker := &RedirectTracker{}
	transport.DialContext = pinnedDialer(pinned)
	client := &http.Client{
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: redirectChecker(c, tracker, pinned),
	}
	return &ClientBundle{Client: client, Pinned: pinned, Tracker: tracker, Checker: c}
}

// NewClient builds a policy-pinned ClientBundle.
func NewClient(c *policy.Checker) *ClientBundle {
	return newBundle(c, &http.Transport{ForceAttemptHTTP2: true})
}

// NewTimingClient disables HTTP/2 reuse.
func NewTimingClient(c *policy.Checker) *ClientBundle {
	return newBundle(c, &http.Transport{
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		MaxIdleConns:      0,
		TLSNextProto:      make(map[string]func(string, *tls.Conn) http.RoundTripper),
	})
}

// pinnedDialer dials pinned IPs only.
func pinnedDialer(pinned *PinnedSet) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("httpx: bad dial address %q: %w", addr, err)
		}

		// Host is already an IP: check directly.
		if ip := net.ParseIP(host); ip != nil {
			if !pinned.contains(ip) {
				return nil, fmt.Errorf("httpx: dial to non-pinned IP %s rejected", ip)
			}
			return dialer.DialContext(ctx, network, addr)
		}

		// DNS name: dial only pinned IPs.
		pinned.mu.Lock()
		ips := make([]net.IP, len(pinned.ips))
		copy(ips, pinned.ips)
		pinned.mu.Unlock()
		if len(ips) == 0 {
			return nil, fmt.Errorf("httpx: no pinned IPs for %s", addr)
		}

		var lastErr error
		for _, ip := range ips {
			dialAddr := net.JoinHostPort(ip.String(), port)
			conn, dialErr := dialer.DialContext(ctx, network, dialAddr)
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, fmt.Errorf("httpx: all pinned IPs failed for %s: %w", addr, lastErr)
	}
}

// redirectChecker rechecks and records hops.
func redirectChecker(c *policy.Checker, tracker *RedirectTracker, pinned *PinnedSet) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		from := via[len(via)-1].URL.String()
		to := req.URL.String()
		statusCode := 0
		if req.Response != nil {
			statusCode = req.Response.StatusCode
		}

		err := c.CheckRedirect(from, to)
		tracker.mu.Lock()
		tracker.hops = append(tracker.hops, RedirectHop{
			From:       from,
			To:         to,
			StatusCode: statusCode,
			Allowed:    err == nil,
		})
		tracker.mu.Unlock()
		if err != nil {
			return fmt.Errorf("httpx: redirect rejected: %w", err)
		}

		// Re-pin the redirect target.
		safe, urlErr := c.CheckURL(to, policy.PhaseRedirect)
		if urlErr != nil {
			return fmt.Errorf("httpx: redirect target check: %w", urlErr)
		}
		pinned.Add(safe.PinnedIP)

		return nil
	}
}
