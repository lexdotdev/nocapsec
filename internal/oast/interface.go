// Package oast: callback tokens + polling.
// Proves blind vulns.
package oast

import (
	"context"
	"time"
)

// OASTToken: neutral token a validator slots in.
type OASTToken struct {
	CorrelationID string
	Domain        string
	URLHTTP       string
	URLHTTPS      string
	// Purpose: ssrf | blind_xss | xxe |
	// open_redirect | command_injection.
	Purpose string
	// ExpectedProtocols: callback protocols that prove.
	ExpectedProtocols []string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// Interaction: neutral record of one callback.
type Interaction struct {
	CorrelationID string
	// Protocol: dns | http | https | smtp | ldap.
	Protocol   string
	SourceIP   string
	UserAgent  string
	Timestamp  time.Time
	RawRequest []byte
}

// OAST allocates, polls, releases tokens.
type OAST interface {
	NewInteraction(ctx context.Context, purpose string) (*OASTToken, error)
	Poll(ctx context.Context, tokenID string, since time.Time) ([]Interaction, error)
	// Close expires the token.
	Close(ctx context.Context, tokenID string) error
}
