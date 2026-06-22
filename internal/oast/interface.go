// Package oast handles blind callbacks.
package oast

import (
	"context"
	"time"
)

// OASTToken is inserted by validators.
type OASTToken struct {
	CorrelationID string
	Domain        string
	URLHTTP       string
	URLHTTPS      string
	// URLRedirect points to /r/.
	URLRedirect string
	// Purpose selects proof semantics.
	Purpose string
	// ExpectedProtocols can prove the token.
	ExpectedProtocols []string
	CreatedAt         time.Time
	ExpiresAt         time.Time
}

// Interaction records one callback.
type Interaction struct {
	CorrelationID string
	// Protocol is backend-neutral.
	Protocol   string
	SourceIP   string
	UserAgent  string
	Timestamp  time.Time
	RawRequest []byte
}

// OAST allocates and polls tokens.
type OAST interface {
	NewInteraction(ctx context.Context, purpose string) (*OASTToken, error)
	Poll(ctx context.Context, tokenID string, since time.Time) ([]Interaction, error)
	// Close expires a token.
	Close(ctx context.Context, tokenID string) error
}
