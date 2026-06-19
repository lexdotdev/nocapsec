package policy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// ConnectProxy is an HTTP CONNECT proxy that enforces scheme/host/port/IP
// policy at the CONNECT request without decrypting TLS. It delegates host/IP
// validation to a Checker.
type ConnectProxy struct {
	Checker  *Checker
	listener net.Listener
	srv      *http.Server
	once     sync.Once
}

// NewConnectProxy builds a policy-enforcing CONNECT proxy bound to a random
// localhost port. Call Addr after Start, Shutdown when done.
func NewConnectProxy(c *Checker) (*ConnectProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("policy: proxy listen: %w", err)
	}
	p := &ConnectProxy{Checker: c, listener: ln}
	p.srv = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return p, nil
}

// Start begins serving in the background.
func (p *ConnectProxy) Start() {
	p.once.Do(func() {
		go func() { _ = p.srv.Serve(p.listener) }()
	})
}

// Addr returns the proxy's listen address as "host:port".
func (p *ConnectProxy) Addr() string { return p.listener.Addr().String() }

// URL returns the proxy address as an HTTP URL for chromedp.
func (p *ConnectProxy) URL() string { return "http://" + p.Addr() }

// Shutdown gracefully stops the proxy.
func (p *ConnectProxy) Shutdown(ctx context.Context) error {
	return p.srv.Shutdown(ctx)
}

// ServeHTTP handles CONNECT requests; non-CONNECT is rejected.
func (p *ConnectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
		return
	}

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	// Build a synthetic URL for the policy checker.
	scheme := schemeHTTPS
	if port == "80" {
		scheme = schemeHTTP
	}
	raw := scheme + "://" + host
	if port != "" {
		raw += ":" + port
	}
	raw += "/"

	safe, checkErr := p.Checker.CheckURL(raw, PhaseBrowserNav) //nolint:contextcheck // CheckURL uses context.Background internally by design
	if checkErr != nil {
		http.Error(w, "policy: "+checkErr.Error(), http.StatusForbidden)
		return
	}

	// Connect to one of the pinned IPs.
	var upstream net.Conn
	for _, ip := range safe.PinnedIP {
		dialAddr := net.JoinHostPort(ip.String(), port)
		upstream, err = net.DialTimeout("tcp", dialAddr, 10*time.Second) //nolint:gosec // dialAddr is from policy-pinned IPs
		if err == nil {
			break
		}
	}
	if upstream == nil {
		http.Error(w, "connect failed", http.StatusBadGateway)
		return
	}
	defer upstream.Close() //nolint:errcheck // best-effort cleanup

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}

	client, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close() //nolint:errcheck // best-effort cleanup

	// Write 200 on the raw connection after hijacking.
	_, _ = fmt.Fprint(buf, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = buf.Flush()

	relay(client, upstream)
}

// relay copies bytes bidirectionally between a and b.
func relay(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}
	go cp(upstream, client)
	go cp(client, upstream)
	wg.Wait()
}
