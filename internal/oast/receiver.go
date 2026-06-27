package oast

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Receiver serves local HTTP and DNS.
type Receiver struct {
	domain        string
	advertiseHost string
	clock         Clock

	httpSrv      *http.Server
	dnsConn      *net.UDPConn
	httpAddr     string
	dnsAddr      string
	callbackHost string

	mu           sync.Mutex
	interactions map[string][]Interaction // by correlationID
}

// SetCallbackHost overrides callback host.
func (r *Receiver) SetCallbackHost(host string) { r.callbackHost = host }

// NewReceiver builds an embedded receiver.
func NewReceiver(domain, advertiseHost string) *Receiver {
	return &Receiver{
		domain:        domain,
		advertiseHost: advertiseHost,
		clock:         wallClock{},
		interactions:  make(map[string][]Interaction),
	}
}

// Start serves HTTP and DNS.
func (r *Receiver) Start(httpAddr, dnsAddr string) error {
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("oast: http listen: %w", err)
	}
	r.httpAddr = ln.Addr().String()
	r.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(r.handleHTTP),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = r.httpSrv.Serve(ln) }()

	udpAddr, err := net.ResolveUDPAddr("udp", dnsAddr)
	if err != nil {
		_ = r.httpSrv.Close()
		return fmt.Errorf("oast: resolve dns addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = r.httpSrv.Close()
		return fmt.Errorf("oast: dns listen: %w", err)
	}
	r.dnsConn = conn
	r.dnsAddr = conn.LocalAddr().String()
	go r.serveDNS()
	return nil
}

// HTTPAddr returns the bound HTTP addr.
func (r *Receiver) HTTPAddr() string { return r.httpAddr }

// DNSAddr returns the bound DNS addr.
func (r *Receiver) DNSAddr() string { return r.dnsAddr }

// callbackBase applies callbackHost.
func (r *Receiver) callbackBase() string {
	if r.callbackHost == "" {
		return r.httpAddr
	}
	if _, port, err := net.SplitHostPort(r.httpAddr); err == nil {
		return net.JoinHostPort(r.callbackHost, port)
	}
	return r.httpAddr
}

func (r *Receiver) NewInteraction(_ context.Context, purpose string) (*OASTToken, error) {
	corrID, err := randomCorrelationID()
	if err != nil {
		return nil, err
	}
	now := r.clock.Now()
	cbHost := r.callbackBase()
	cb := fmt.Sprintf("http://%s/cb/%s", cbHost, corrID)
	redir := fmt.Sprintf("http://%s/r/%s", cbHost, corrID)
	return &OASTToken{
		CorrelationID:     corrID,
		Domain:            corrID + "." + r.domain,
		URLHTTP:           cb,
		URLHTTPS:          cb,
		URLRedirect:       redir,
		Purpose:           purpose,
		ExpectedProtocols: expectedProtocols(purpose),
		CreatedAt:         now,
		ExpiresAt:         now.Add(tokenTTL(purpose)),
	}, nil
}

func (r *Receiver) Poll(_ context.Context, tokenID string, since time.Time) ([]Interaction, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Interaction
	for _, ix := range r.interactions[tokenID] {
		if !ix.Timestamp.Before(since) {
			out = append(out, ix)
		}
	}
	return out, nil
}

// Close is per-token no-op.
func (r *Receiver) Close(_ context.Context, _ string) error { return nil }

// Stop closes listeners.
func (r *Receiver) Stop() {
	if r.httpSrv != nil {
		_ = r.httpSrv.Close()
	}
	if r.dnsConn != nil {
		_ = r.dnsConn.Close()
	}
}

func (r *Receiver) record(corrID, protocol, sourceIP, userAgent, raw string) {
	ix := Interaction{
		CorrelationID: corrID,
		Protocol:      normalizeProtocol(protocol),
		SourceIP:      sourceIP,
		UserAgent:     userAgent,
		Timestamp:     r.clock.Now(),
		RawRequest:    []byte(raw),
	}
	r.mu.Lock()
	r.interactions[corrID] = append(r.interactions[corrID], ix)
	r.mu.Unlock()
}

func (r *Receiver) handleHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case strings.HasPrefix(req.URL.Path, "/cb/"):
		corrID := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/cb/"), "/", 2)[0]
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			host = req.RemoteAddr
		}
		r.record(corrID, "http", host, req.UserAgent(), req.Method+" "+req.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))

	case strings.HasPrefix(req.URL.Path, "/r/"):
		// Only /cb/ records proof.
		corrID := strings.SplitN(strings.TrimPrefix(req.URL.Path, "/r/"), "/", 2)[0]
		dest := fmt.Sprintf("http://%s/cb/%s", r.callbackBase(), corrID)
		http.Redirect(w, req, dest, http.StatusFound)

	default:
		http.NotFound(w, req)
	}
}

func (r *Receiver) serveDNS() {
	buf := make([]byte, 512)
	for {
		n, addr, err := r.dnsConn.ReadFromUDP(buf)
		if err != nil {
			return // listener closed
		}
		query := buf[:n]
		if qname := dnsQName(query); qname != "" {
			corrID := strings.SplitN(qname, ".", 2)[0]
			r.record(corrID, "dns", addr.IP.String(), "", qname)
		}
		if reply := dnsAnswer(query, r.advertiseHost); reply != nil {
			_, _ = r.dnsConn.WriteToUDP(reply, addr)
		}
	}
}

// dnsQName parses QNAME.
func dnsQName(query []byte) string {
	if len(query) <= 12 {
		return ""
	}
	var labels []string
	i := 12
	for i < len(query) && query[i] != 0 {
		n := int(query[i])
		if i+1+n > len(query) {
			return ""
		}
		labels = append(labels, string(query[i+1:i+1+n]))
		i += n + 1
	}
	return strings.Join(labels, ".")
}

// dnsAnswer builds an A response.
func dnsAnswer(query []byte, advertiseHost string) []byte {
	if len(query) <= 12 {
		return nil
	}
	ip := net.ParseIP(advertiseHost).To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1).To4()
	}
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	qend := i + 1 + 4 // null label + qtype + qclass
	if qend > len(query) {
		return nil
	}
	resp := make([]byte, 0, qend+16)
	resp = append(resp, query[:2]...)                                   // echo ID
	resp = append(resp, 0x81, 0x80)                                     // flags: response, recursion
	resp = append(resp, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00) // 1 q, 1 a
	resp = append(resp, query[12:qend]...)                              // question
	resp = append(resp, 0xc0, 0x0c)                                     // name pointer to qname
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)                         // type A, class IN
	resp = append(resp, 0x00, 0x00, 0x00, 0x3c)                         // TTL 60
	resp = append(resp, 0x00, 0x04)                                     // rdlength 4
	resp = append(resp, ip[0], ip[1], ip[2], ip[3])                     // A record
	return resp
}
