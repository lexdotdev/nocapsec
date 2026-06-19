package oast_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/oast"
)

// --- test clock ---

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Since(t time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Sub(t)
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// --- Fake backend tests ---

func TestFakeNewInteraction(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, err := f.NewInteraction(context.Background(), "ssrf")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}
	if tok.CorrelationID == "" {
		t.Fatal("empty CorrelationID")
	}
	if tok.Purpose != "ssrf" {
		t.Fatalf("purpose = %q, want ssrf", tok.Purpose)
	}
	if !strings.Contains(tok.Domain, "oast.test") {
		t.Fatalf("domain = %q, want contains oast.test", tok.Domain)
	}
	if tok.URLHTTP == "" || tok.URLHTTPS == "" {
		t.Fatal("empty URL")
	}
	if len(tok.ExpectedProtocols) == 0 {
		t.Fatal("no expected protocols")
	}
}

func TestFakePollReturnsInjectedInteractions(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, err := f.NewInteraction(context.Background(), "ssrf")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}

	since := clk.Now()
	clk.Advance(5 * time.Second)

	f.AddInteraction(tok.CorrelationID, oast.Interaction{
		Protocol:  "dns",
		SourceIP:  "10.0.0.1",
		Timestamp: clk.Now(),
	})

	ixns, err := f.Poll(context.Background(), tok.CorrelationID, since)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 1 {
		t.Fatalf("got %d interactions, want 1", len(ixns))
	}
	if ixns[0].Protocol != "dns" {
		t.Fatalf("protocol = %q, want dns", ixns[0].Protocol)
	}
	if ixns[0].CorrelationID != tok.CorrelationID {
		t.Fatalf("correlationID mismatch")
	}
}

func TestFakePollFiltersBySince(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, _ := f.NewInteraction(context.Background(), "xxe")

	earlyTS := clk.Now()
	clk.Advance(10 * time.Second)
	f.AddInteraction(tok.CorrelationID, oast.Interaction{
		Protocol:  "dns",
		Timestamp: earlyTS,
	})

	lateTS := clk.Now()
	clk.Advance(5 * time.Second)
	f.AddInteraction(tok.CorrelationID, oast.Interaction{
		Protocol:  "http",
		Timestamp: clk.Now(),
	})

	// Poll since lateTS should skip the first interaction.
	ixns, err := f.Poll(context.Background(), tok.CorrelationID, lateTS)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 1 {
		t.Fatalf("got %d interactions, want 1", len(ixns))
	}
	if ixns[0].Protocol != "http" {
		t.Fatalf("protocol = %q, want http", ixns[0].Protocol)
	}
}

func TestFakeCloseRemovesToken(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, _ := f.NewInteraction(context.Background(), "ssrf")

	if err := f.Close(context.Background(), tok.CorrelationID); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err := f.Poll(context.Background(), tok.CorrelationID, time.Time{})
	if err == nil {
		t.Fatal("expected error polling closed token")
	}
}

func TestFakeCloseUnknownToken(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	if err := f.Close(context.Background(), "nonexistent"); err == nil {
		t.Fatal("expected error closing unknown token")
	}
}

func TestFakeTokenTTL(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	// blind_xss gets 15min TTL
	tok, _ := f.NewInteraction(context.Background(), "blind_xss")
	ttl := tok.ExpiresAt.Sub(tok.CreatedAt)
	if ttl != 900*time.Second {
		t.Fatalf("blind_xss TTL = %v, want 900s", ttl)
	}

	// ssrf gets 120s TTL
	tok2, _ := f.NewInteraction(context.Background(), "ssrf")
	ttl2 := tok2.ExpiresAt.Sub(tok2.CreatedAt)
	if ttl2 != 120*time.Second {
		t.Fatalf("ssrf TTL = %v, want 120s", ttl2)
	}
}

// --- Source attribution tests ---

func TestClassifySource(t *testing.T) {
	tests := []struct {
		name       string
		ix         oast.Interaction
		targetIPs  []string
		verifierUA string
		want       oast.SourceClass
	}{
		{
			name:      "target infra IP",
			ix:        oast.Interaction{SourceIP: "10.0.0.5", UserAgent: "Python/3.11"},
			targetIPs: []string{"10.0.0.5"},
			want:      oast.SourceTargetInfra,
		},
		{
			name:       "verifier browser UA",
			ix:         oast.Interaction{SourceIP: "203.0.113.1", UserAgent: "HeadlessChrome/125"},
			targetIPs:  []string{"10.0.0.5"},
			verifierUA: "HeadlessChrome",
			want:       oast.SourceVerifierBrowser,
		},
		{
			name:       "noise",
			ix:         oast.Interaction{SourceIP: "198.51.100.1", UserAgent: "Shodan"},
			targetIPs:  []string{"10.0.0.5"},
			verifierUA: "HeadlessChrome",
			want:       oast.SourceNoise,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oast.ClassifySource(tt.ix, tt.targetIPs, tt.verifierUA)
			if got != tt.want {
				t.Fatalf("ClassifySource = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterByProtocol(t *testing.T) {
	ixns := []oast.Interaction{
		{Protocol: "dns"},
		{Protocol: "http"},
		{Protocol: "smtp"},
		{Protocol: "https"},
	}
	got := oast.FilterByProtocol(ixns, []string{"dns", "http"})
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	for _, ix := range got {
		if ix.Protocol != "dns" && ix.Protocol != "http" {
			t.Fatalf("unexpected protocol %q", ix.Protocol)
		}
	}
}

func TestRequireSourceNotVerifier(t *testing.T) {
	ixns := []oast.Interaction{
		{SourceIP: "10.0.0.5", UserAgent: "Python/3.11"},       // target
		{SourceIP: "203.0.113.1", UserAgent: "HeadlessChrome"}, // verifier
		{SourceIP: "198.51.100.1", UserAgent: "Shodan"},        // noise
	}
	got := oast.RequireSourceNotVerifier(ixns, []string{"10.0.0.5"}, "HeadlessChrome")
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 (only target infra)", len(got))
	}
	if got[0].SourceIP != "10.0.0.5" {
		t.Fatalf("expected target IP, got %q", got[0].SourceIP)
	}
}

// --- PollUntilMatch tests ---

func TestPollUntilMatchFindsInteraction(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, _ := f.NewInteraction(context.Background(), "ssrf")
	since := clk.Now()

	// Schedule an interaction to appear soon.
	clk.Advance(3 * time.Second)
	f.AddInteraction(tok.CorrelationID, oast.Interaction{
		Protocol:  "dns",
		SourceIP:  "10.0.0.1",
		Timestamp: clk.Now(),
	})

	cfg := oast.PollConfig{
		Window:      30 * time.Second,
		InitialWait: 1 * time.Millisecond,
		MinInterval: 1 * time.Millisecond,
		MaxInterval: 10 * time.Millisecond,
		Multiplier:  1.5,
	}
	result, err := oast.PollUntilMatch(context.Background(), f, tok.CorrelationID, since, cfg, clk)
	if err != nil {
		t.Fatalf("PollUntilMatch: %v", err)
	}
	if result.Expired {
		t.Fatal("unexpectedly expired")
	}
	if len(result.Interactions) != 1 {
		t.Fatalf("got %d interactions, want 1", len(result.Interactions))
	}
}

func TestPollUntilMatchExpires(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, _ := f.NewInteraction(context.Background(), "ssrf")
	since := clk.Now()

	// Advance past window to simulate expiry.
	clk.Advance(200 * time.Second)

	cfg := oast.PollConfig{
		Window:      1 * time.Millisecond,
		InitialWait: 1 * time.Millisecond,
		MinInterval: 1 * time.Millisecond,
		MaxInterval: 1 * time.Millisecond,
		Multiplier:  1.0,
	}
	result, err := oast.PollUntilMatch(context.Background(), f, tok.CorrelationID, since, cfg, clk)
	if err != nil {
		t.Fatalf("PollUntilMatch: %v", err)
	}
	if !result.Expired {
		t.Fatal("expected expired result")
	}
}

func TestPollUntilMatchCancellation(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tok, _ := f.NewInteraction(context.Background(), "ssrf")
	since := clk.Now()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediate cancel

	cfg := oast.PollConfig{
		Window:      120 * time.Second,
		InitialWait: 1 * time.Hour, // would block forever
		MinInterval: 1 * time.Second,
		MaxInterval: 1 * time.Second,
		Multiplier:  1.0,
	}
	_, err := oast.PollUntilMatch(ctx, f, tok.CorrelationID, since, cfg, clk)
	if err == nil {
		t.Fatal("expected context error")
	}
}

// --- Interactsh client tests (against fake HTTP server) ---

func TestInteractshClientLifecycle(t *testing.T) {
	// Build a fake interactsh-server that handles register/poll/deregister.
	var (
		mu            sync.Mutex
		registeredIDs []string
		serverPrivKey *rsa.PrivateKey
		clientPubKey  *rsa.PublicKey
		aesKeyRaw     []byte
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/register" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			var req struct {
				PublicKey     string `json:"public-key"`
				SecretKey     string `json:"secret-key"`
				CorrelationID string `json:"correlation-id"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			// Parse client's public key.
			block, _ := decPEM([]byte(req.PublicKey))
			if block == nil {
				http.Error(w, "bad pem", http.StatusBadRequest)
				return
			}
			pub, err := x509.ParsePKIXPublicKey(block)
			if err != nil {
				http.Error(w, "bad pubkey", http.StatusBadRequest)
				return
			}

			mu.Lock()
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				http.Error(w, "not rsa key", http.StatusBadRequest)
				mu.Unlock()
				return
			}
			clientPubKey = rsaPub
			registeredIDs = append(registeredIDs, req.CorrelationID)
			aesKeyRaw, _ = base64.StdEncoding.DecodeString(req.SecretKey)
			mu.Unlock()

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))

		case r.URL.Path == "/poll" && r.Method == http.MethodGet:
			mu.Lock()
			key := aesKeyRaw
			pubKey := clientPubKey
			mu.Unlock()

			if pubKey == nil || len(key) == 0 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":[],"aes_key":""}`))
				return
			}

			// Build a fake interaction payload.
			interaction := map[string]string{
				"protocol":       "dns",
				"raw-request":    "User-Agent: test-agent\nHost: oast.test",
				"remote-address": "10.0.0.5",
				"timestamp":      time.Date(2026, 6, 1, 0, 1, 0, 0, time.UTC).Format(time.RFC3339),
			}
			plain, _ := json.Marshal(interaction)
			encrypted := encryptPayload(t, key, plain)

			// Encrypt the AES key with client's public key.
			encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, key, nil)
			if err != nil {
				http.Error(w, "encrypt failed", http.StatusInternalServerError)
				return
			}

			resp := map[string]any{
				"data":    []string{encrypted},
				"aes_key": base64.StdEncoding.EncodeToString(encKey),
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case r.URL.Path == "/deregister" && r.Method == http.MethodPost:
			mu.Lock()
			// Just accept.
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Use a private key for the "server" side.
	serverPrivKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	_ = serverPrivKey // unused in this simple test server

	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	client := oast.NewInteractshClient(srv.URL, "oast.test",
		oast.WithHTTPDoer(srv.Client()),
		oast.WithClock(clk),
	)

	ctx := context.Background()

	// Register.
	tok, err := client.NewInteraction(ctx, "ssrf")
	if err != nil {
		t.Fatalf("NewInteraction: %v", err)
	}
	if tok.CorrelationID == "" {
		t.Fatal("empty CorrelationID")
	}
	if tok.Purpose != "ssrf" {
		t.Fatalf("purpose = %q", tok.Purpose)
	}

	mu.Lock()
	if len(registeredIDs) != 1 {
		t.Fatalf("server saw %d registrations", len(registeredIDs))
	}
	mu.Unlock()

	// Poll.
	since := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ixns, err := client.Poll(ctx, tok.CorrelationID, since)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(ixns) != 1 {
		t.Fatalf("got %d interactions, want 1", len(ixns))
	}
	if ixns[0].Protocol != "dns" {
		t.Fatalf("protocol = %q, want dns", ixns[0].Protocol)
	}
	if ixns[0].SourceIP != "10.0.0.5" {
		t.Fatalf("sourceIP = %q", ixns[0].SourceIP)
	}

	// Close.
	if err := client.Close(ctx, tok.CorrelationID); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Polling a closed token should fail.
	_, err = client.Poll(ctx, tok.CorrelationID, since)
	if err == nil {
		t.Fatal("expected error polling closed token")
	}
}

func TestInteractshClientPollUnknownToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := oast.NewInteractshClient(srv.URL, "oast.test",
		oast.WithHTTPDoer(srv.Client()),
	)
	_, err := client.Poll(context.Background(), "nonexistent", time.Time{})
	if err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestInteractshClientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := oast.NewInteractshClient(srv.URL, "oast.test",
		oast.WithHTTPDoer(srv.Client()),
	)
	_, err := client.NewInteraction(context.Background(), "ssrf")
	if err == nil {
		t.Fatal("expected error on server 500")
	}
}

func TestExpectedProtocols(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	f := oast.NewFake(clk, "oast.test")

	tests := []struct {
		purpose string
		want    []string
	}{
		{"ssrf", []string{"dns", "http", "https"}},
		{"blind_xss", []string{"http", "https"}},
		{"xxe", []string{"dns", "http", "https"}},
		{"command_injection", []string{"dns", "http"}},
		{"open_redirect", []string{"http", "https"}},
	}
	for _, tt := range tests {
		t.Run(tt.purpose, func(t *testing.T) {
			tok, _ := f.NewInteraction(context.Background(), tt.purpose)
			if fmt.Sprint(tok.ExpectedProtocols) != fmt.Sprint(tt.want) {
				t.Fatalf("got %v, want %v", tok.ExpectedProtocols, tt.want)
			}
		})
	}
}

// --- test helpers ---

func decPEM(data []byte) ([]byte, []byte) {
	var lines []string
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "-----BEGIN") {
			inBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, "-----END") {
			inBlock = false
			continue
		}
		if inBlock && trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) == 0 {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		return nil, nil
	}
	return decoded, nil
}

func encryptPayload(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand iv: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv) //nolint:staticcheck // matching Interactsh wire format
	stream.XORKeyStream(ciphertext, plaintext)

	combined := make([]byte, 0, len(iv)+len(ciphertext))
	combined = append(combined, iv...)
	combined = append(combined, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined)
}
