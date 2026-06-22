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

// ConnectProxy gates CONNECT.
type ConnectProxy struct {
	Checker  *Checker
	listener net.Listener
	srv      *http.Server
	once     sync.Once
}

// NewConnectProxy binds localhost.
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

// Addr returns host:port.
func (p *ConnectProxy) Addr() string { return p.listener.Addr().String() }

// URL returns the proxy address as an HTTP URL.
func (p *ConnectProxy) URL() string { return "http://" + p.Addr() }

// Shutdown gracefully stops the proxy.
func (p *ConnectProxy) Shutdown(ctx context.Context) error {
	return p.srv.Shutdown(ctx)
}

// ServeHTTP gates browser proxy traffic.
func (p *ConnectProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		p.serveForward(w, r)
		return
	}

	p.serveConnect(w, r)
}

func (p *ConnectProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	// Synthetic URL for policy.
	scheme := schemeHTTPS
	if port == "80" {
		scheme = schemeHTTP
	}
	raw := scheme + "://" + host
	if port != "" {
		raw += ":" + port
	}
	raw += "/"

	safe, checkErr := p.Checker.CheckURL(raw, PhaseBrowserNav) //nolint:contextcheck // CheckURL owns timeout
	if checkErr != nil {
		http.Error(w, "policy: "+checkErr.Error(), http.StatusForbidden)
		return
	}

	// Dial only pinned IPs.
	var upstream net.Conn
	for _, ip := range safe.PinnedIP {
		dialAddr := net.JoinHostPort(ip.String(), port)
		upstream, err = net.DialTimeout("tcp", dialAddr, 10*time.Second) //nolint:gosec // pinned IP
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

	// Write on the raw connection.
	_, _ = fmt.Fprint(buf, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = buf.Flush()

	relay(client, upstream)
}

func (p *ConnectProxy) serveForward(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return
	}

	safe, checkErr := p.Checker.CheckURL(r.URL.String(), PhaseBrowserNav) //nolint:contextcheck // CheckURL owns timeout
	if checkErr != nil {
		http.Error(w, "policy: "+checkErr.Error(), http.StatusForbidden)
		return
	}

	out := r.Clone(r.Context())
	out.URL = safe.URL
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	dropHopHeaders(out.Header)

	resp, err := roundTripPinned(out, safe.PinnedIP)
	if err != nil {
		http.Error(w, "forward failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close() //nolint:errcheck // proxy response body

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func roundTripPinned(req *http.Request, ips []net.IP) (*http.Response, error) {
	tr := &http.Transport{DialContext: pinnedProxyDialer(ips)}
	defer tr.CloseIdleConnections()
	return tr.RoundTrip(req)
}

func pinnedProxyDialer(ips []net.IP) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("policy: no pinned IPs for %s", addr)
		}
		var lastErr error
		for _, ip := range ips {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}
}

func dropHopHeaders(h http.Header) {
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// relay copies both directions.
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
