package policy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestConnectProxy_ForwardsHTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "" {
			t.Error("missing host")
		}
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	host, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := URLPolicy{
		AllowedSchemes:  []string{"http"},
		AllowedHosts:    []string{"app.example.com"},
		BlockLoopback:   false,
		BlockPrivateIPs: false,
	}
	c := NewChecker(p, fakeResolver{ips: []net.IP{net.ParseIP(host)}})
	proxy, err := NewConnectProxy(c)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Start()
	defer func() { _ = proxy.Shutdown(context.Background()) }()

	proxyURL, err := url.Parse(proxy.URL())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://app.example.com:" + port + "/") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "proxied" {
		t.Fatalf("body = %q, want proxied", body)
	}
}

func TestConnectProxy_RejectsOutOfScope(t *testing.T) {
	c := NewChecker(scopePolicy(), publicResolver())
	proxy, err := NewConnectProxy(c)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Start()
	defer func() { _ = proxy.Shutdown(context.Background()) }()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	_, err = fmt.Fprintf(conn, "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestConnectProxy_RejectsBlockedIP(t *testing.T) {
	p := ipPolicy()
	c := NewChecker(p, publicResolver())
	proxy, err := NewConnectProxy(c)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Start()
	defer func() { _ = proxy.Shutdown(context.Background()) }()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	_, err = fmt.Fprintf(conn, "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestConnectProxy_AllowsInScope(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()

	_, upPort, _ := net.SplitHostPort(upstream.Addr().String())

	p := URLPolicy{
		AllowedSchemes:  []string{"http", "https"},
		AllowedHosts:    []string{"127.0.0.1"},
		BlockLoopback:   false,
		BlockPrivateIPs: true,
	}
	resolver := fakeResolver{ips: []net.IP{net.ParseIP("127.0.0.1")}}
	c := NewChecker(p, resolver)
	proxy, err := NewConnectProxy(c)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Start()
	defer func() { _ = proxy.Shutdown(context.Background()) }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	_, err = fmt.Fprintf(conn, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n", upPort, upPort)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil) //nolint:bodyclose // CONNECT tunnel, no body
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	select {
	case upConn := <-accepted:
		_ = upConn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never received connection")
	}
}

func TestConnectProxy_URL(t *testing.T) {
	c := NewChecker(scopePolicy(), publicResolver())
	proxy, err := NewConnectProxy(c)
	if err != nil {
		t.Fatal(err)
	}
	proxy.Start()
	defer func() { _ = proxy.Shutdown(context.Background()) }()

	u := proxy.URL()
	if u == "" {
		t.Fatal("URL() returned empty")
	}
	if u[:7] != "http://" {
		t.Fatalf("URL() = %q, want http:// prefix", u)
	}
}
