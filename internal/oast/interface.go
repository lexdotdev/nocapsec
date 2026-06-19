// Package oast allocates out-of-band callback tokens and polls for the
// DNS/HTTP/HTTPS/SMTP interactions that prove blind vulnerabilities. The
// concrete backend (Interactsh) hides behind the OAST interface so proof rules
// depend only on protocol-neutral models.
package oast

import (
	"context"
	"time"
)

// OASTToken is what a validator inserts into a declared mutation slot. It is
// backend-neutral; Interactsh-specific concepts never appear here.
type OASTToken struct {
	CorrelationID string
	Domain        string
	URLHTTP       string
	URLHTTPS      string
	// Purpose is one of: ssrf | blind_xss | xxe | open_redirect | command_injection.
	Purpose string
	// ExpectedProtocols lists the callback protocols that count as proof,
	// e.g. dns | http | https | smtp | ldap.
	ExpectedProtocols []string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// Interaction is the backend-neutral record of a single callback.
type Interaction struct {
	CorrelationID string
	// Protocol is one of: dns | http | https | smtp | ldap.
	Protocol   string
	SourceIP   string
	UserAgent  string
	Timestamp  time.Time
	RawRequest []byte
}

// OAST allocates unique callback tokens, polls for matching interactions, and
// releases tokens once their poll window closes.
type OAST interface {
	NewInteraction(ctx context.Context, purpose string) (*OASTToken, error)
	Poll(ctx context.Context, tokenID string, since time.Time) ([]Interaction, error)
	// Close expires the token.
	Close(ctx context.Context, tokenID string) error
}
