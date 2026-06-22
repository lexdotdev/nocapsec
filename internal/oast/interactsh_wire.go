package oast

import (
	"strings"
	"time"
)

type registerRequest struct {
	PublicKey     string `json:"public-key"`
	SecretKey     string `json:"secret-key"`
	CorrelationID string `json:"correlation-id"`
}

type deregisterRequest struct {
	CorrelationID string `json:"correlation-id"`
	SecretKey     string `json:"secret-key"`
}

type pollResponse struct {
	Data   []string `json:"data"`
	AESKey string   `json:"aes_key"`
}

type interactshInteraction struct {
	Protocol      string `json:"protocol"`
	RawRequest    string `json:"raw-request"`
	RemoteAddress string `json:"remote-address"`
	Timestamp     string `json:"timestamp"`
	HTTPRequest   string `json:"http-request,omitempty"`
	SMTPFrom      string `json:"smtp-from,omitempty"`
}

// normalizeProtocol lowercases names.
func normalizeProtocol(raw string) string {
	return strings.ToLower(raw)
}

// extractUserAgent reads User-Agent.
func extractUserAgent(e interactshInteraction) string {
	// Prefer embedded HTTP request.
	raw := e.HTTPRequest
	if raw == "" {
		raw = e.RawRequest
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "user-agent:") {
			return strings.TrimSpace(line[len("user-agent:"):])
		}
	}
	return ""
}

// parseInteractshTime parses wire time.
func parseInteractshTime(s string) time.Time {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
