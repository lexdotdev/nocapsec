package oast_test

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/oast"
)

func newReceiver(t *testing.T) *oast.Receiver {
	t.Helper()
	r := oast.NewReceiver("oast.test", "127.0.0.1")
	if err := r.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(r.Stop)
	return r
}

func TestReceiverNewInteraction(t *testing.T) {
	r := newReceiver(t)
	tok, err := r.NewInteraction(context.Background(), "ssrf")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}
	if tok.CorrelationID == "" {
		t.Fatal("empty correlation id")
	}
	wantCB := "http://" + r.HTTPAddr() + "/cb/" + tok.CorrelationID
	if tok.URLHTTP != wantCB || tok.URLHTTPS != wantCB {
		t.Fatalf("callback URL = %q/%q, want %q", tok.URLHTTP, tok.URLHTTPS, wantCB)
	}
	if !strings.HasSuffix(tok.Domain, ".oast.test") || !strings.HasPrefix(tok.Domain, tok.CorrelationID) {
		t.Fatalf("domain = %q", tok.Domain)
	}
	if len(tok.ExpectedProtocols) == 0 {
		t.Fatal("no expected protocols")
	}
}

func TestReceiverHTTPCallback(t *testing.T) {
	r := newReceiver(t)
	tok, err := r.NewInteraction(context.Background(), "ssrf")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}

	since := time.Now()
	req, err := http.NewRequest(http.MethodGet, tok.URLHTTP, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("User-Agent", "Python-urllib/3.11")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_ = resp.Body.Close()

	ixns, err := r.Poll(context.Background(), tok.CorrelationID, since)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 1 {
		t.Fatalf("got %d interactions, want 1", len(ixns))
	}
	ix := ixns[0]
	if ix.Protocol != "http" || ix.UserAgent != "Python-urllib/3.11" || ix.SourceIP == "" {
		t.Fatalf("interaction = %+v", ix)
	}
}

// Redirector only records followed /cb/.
func TestReceiverRedirector(t *testing.T) {
	r := newReceiver(t)
	tok, err := r.NewInteraction(context.Background(), "ssrf")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}
	if tok.URLRedirect == "" {
		t.Fatal("URLRedirect is empty")
	}

	since := time.Now()

	// Inspect the 302 directly.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(tok.URLRedirect) //nolint:noctx // test
	if err != nil {
		t.Fatalf("GET redirector: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/cb/"+tok.CorrelationID) {
		t.Fatalf("Location = %q, want /cb/%s", loc, tok.CorrelationID)
	}

	// /r/ does not record proof.
	ixns, err := r.Poll(context.Background(), tok.CorrelationID, since)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 0 {
		t.Fatalf("got %d interactions from /r/ hop, want 0", len(ixns))
	}

	// /cb/ records proof.
	resp2, err := http.Get(loc) //nolint:noctx // test
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_ = resp2.Body.Close()

	ixns, err = r.Poll(context.Background(), tok.CorrelationID, since)
	if err != nil {
		t.Fatalf("Poll after /cb/: %v", err)
	}
	if len(ixns) != 1 {
		t.Fatalf("got %d interactions after /cb/ hit, want 1", len(ixns))
	}
}

func TestReceiverDNSCallback(t *testing.T) {
	r := newReceiver(t)
	tok, err := r.NewInteraction(context.Background(), "command_injection")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}

	since := time.Now()
	conn, err := net.Dial("udp", r.DNSAddr())
	if err != nil {
		t.Fatalf("dial dns: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup

	if _, err := conn.Write(dnsQuery(tok.Domain)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	// Confirm DNS responder answers.
	reply := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}

	ixns, err := pollUntil(r, tok.CorrelationID, since)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 1 {
		t.Fatalf("got %d interactions, want 1", len(ixns))
	}
	if ixns[0].Protocol != "dns" || ixns[0].SourceIP == "" {
		t.Fatalf("interaction = %+v", ixns[0])
	}
}

func TestReceiverPollFiltersBySince(t *testing.T) {
	r := newReceiver(t)
	tok, _ := r.NewInteraction(context.Background(), "ssrf")

	resp, err := http.Get(tok.URLHTTP) //nolint:noctx // test
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	_ = resp.Body.Close()

	// Future since filters the callback.
	ixns, err := r.Poll(context.Background(), tok.CorrelationID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 0 {
		t.Fatalf("got %d interactions, want 0", len(ixns))
	}
}

// pollUntil waits for async DNS record.
func pollUntil(r *oast.Receiver, id string, since time.Time) ([]oast.Interaction, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		ixns, err := r.Poll(context.Background(), id, since)
		if err != nil || len(ixns) > 0 || time.Now().After(deadline) {
			return ixns, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dnsQuery builds an A query.
func dnsQuery(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0x00)       // root label
	q = append(q, 0x00, 0x01) // qtype A
	q = append(q, 0x00, 0x01) // qclass IN
	return q
}
