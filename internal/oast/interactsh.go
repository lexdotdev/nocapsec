package oast

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Interactsh-specific errors.
var (
	ErrRegistration = errors.New("oast: interactsh registration failed")
	ErrDeregister   = errors.New("oast: interactsh deregister failed")
	ErrPollFailed   = errors.New("oast: interactsh poll failed")
	ErrDecrypt      = errors.New("oast: payload decryption failed")
	ErrTokenUnknown = errors.New("oast: unknown token")
)

const (
	interactshKeyBits   = 2048
	defaultTokenTTL     = 120 * time.Second
	blindXSSTokenTTL    = 900 * time.Second
	registerPath        = "/register"
	deregisterPath      = "/deregister"
	pollPath            = "/poll"
	aesKeyLen           = 16
	correlationIDLength = 20
)

// tokenRecord holds a token's decryption keys.
type tokenRecord struct {
	aesKey    []byte
	secretKey string // hex secret sent to server
}

// HTTPDoer executes HTTP requests; for tests.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// interactshClient is the Interactsh-backed OAST.
type interactshClient struct {
	serverURL string
	domain    string
	client    HTTPDoer
	clock     Clock

	mu      sync.Mutex
	privKey *rsa.PrivateKey
	tokens  map[string]*tokenRecord // by correlationID
}

// InteractshOption configures the client.
type InteractshOption func(*interactshClient)

// WithHTTPDoer injects a custom HTTP client.
func WithHTTPDoer(d HTTPDoer) InteractshOption {
	return func(c *interactshClient) { c.client = d }
}

// WithClock injects a custom clock.
func WithClock(cl Clock) InteractshOption {
	return func(c *interactshClient) { c.clock = cl }
}

// NewInteractshClient: OAST on self-hosted server.
func NewInteractshClient(serverURL, domain string, opts ...InteractshOption) OAST {
	c := &interactshClient{
		serverURL: strings.TrimRight(serverURL, "/"),
		domain:    domain,
		client:    http.DefaultClient,
		clock:     wallClock{},
		tokens:    make(map[string]*tokenRecord),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *interactshClient) NewInteraction(ctx context.Context, purpose string) (*OASTToken, error) {
	if err := c.ensureKey(); err != nil {
		return nil, err
	}

	corrID, err := randomCorrelationID()
	if err != nil {
		return nil, err
	}

	aesKey, err := randomBytes(aesKeyLen)
	if err != nil {
		return nil, err
	}
	secretKey := base64.StdEncoding.EncodeToString(aesKey)

	pubDER, err := x509.MarshalPKIXPublicKey(&c.privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("oast: marshal pubkey: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	body := registerRequest{
		PublicKey:     string(pubPEM),
		SecretKey:     secretKey,
		CorrelationID: corrID,
	}
	if err := c.postJSON(ctx, registerPath, body, nil); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistration, err)
	}

	now := c.clock.Now()
	ttl := tokenTTL(purpose)
	tok := &OASTToken{
		CorrelationID:     corrID,
		Domain:            corrID + "." + c.domain,
		URLHTTP:           "http://" + corrID + "." + c.domain,
		URLHTTPS:          "https://" + corrID + "." + c.domain,
		Purpose:           purpose,
		ExpectedProtocols: expectedProtocols(purpose),
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
	}

	c.mu.Lock()
	c.tokens[corrID] = &tokenRecord{
		aesKey:    aesKey,
		secretKey: secretKey,
	}
	c.mu.Unlock()

	return tok, nil
}

func (c *interactshClient) Poll(ctx context.Context, tokenID string, since time.Time) ([]Interaction, error) {
	c.mu.Lock()
	rec, ok := c.tokens[tokenID]
	c.mu.Unlock()
	if !ok {
		return nil, ErrTokenUnknown
	}

	var resp pollResponse
	if err := c.getJSON(ctx, pollPath+"?id="+tokenID+"&secret="+rec.secretKey, &resp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPollFailed, err)
	}

	if len(resp.Data) == 0 && resp.AESKey == "" {
		return nil, nil
	}

	decryptKey := rec.aesKey
	if resp.AESKey != "" {
		dk, err := c.decryptAESKey(resp.AESKey)
		if err != nil {
			return nil, fmt.Errorf("%w: aes key: %w", ErrDecrypt, err)
		}
		decryptKey = dk
	}

	var result []Interaction
	for _, raw := range resp.Data {
		plain, err := decryptPayload(decryptKey, raw)
		if err != nil {
			continue // skip corrupt entries
		}
		var entry interactshInteraction
		if err := json.Unmarshal(plain, &entry); err != nil {
			continue
		}
		ts := parseInteractshTime(entry.Timestamp)
		if ts.Before(since) {
			continue
		}
		result = append(result, Interaction{
			CorrelationID: tokenID,
			Protocol:      normalizeProtocol(entry.Protocol),
			SourceIP:      entry.RemoteAddress,
			UserAgent:     extractUserAgent(entry),
			Timestamp:     ts,
			RawRequest:    []byte(entry.RawRequest),
		})
	}
	return result, nil
}

func (c *interactshClient) Close(ctx context.Context, tokenID string) error {
	c.mu.Lock()
	rec, ok := c.tokens[tokenID]
	if ok {
		delete(c.tokens, tokenID)
	}
	c.mu.Unlock()
	if !ok {
		return ErrTokenUnknown
	}

	body := deregisterRequest{
		CorrelationID: tokenID,
		SecretKey:     rec.secretKey,
	}
	if err := c.postJSON(ctx, deregisterPath, body, nil); err != nil {
		return fmt.Errorf("%w: %w", ErrDeregister, err)
	}
	return nil
}

func tokenTTL(purpose string) time.Duration {
	if purpose == "blind_xss" {
		return blindXSSTokenTTL
	}
	return defaultTokenTTL
}

func expectedProtocols(purpose string) []string {
	switch purpose {
	case "ssrf":
		return []string{"dns", "http", "https"}
	case "blind_xss":
		return []string{"http", "https"}
	case "xxe":
		return []string{"dns", "http", "https"}
	case "command_injection":
		return []string{"dns", "http"}
	case "open_redirect":
		return []string{"http", "https"}
	default:
		return []string{"dns", "http", "https"}
	}
}
