package oast

import (
	"context"
	"time"
)

// interactshClient is the Interactsh-backed OAST implementation. Interactsh
// concepts (registration, polling secrets, AES payloads, dynamic HTTP
// responses) stay confined to this file and never leak into proof rules.
//
// TODO: implement against a self-hosted interactsh-server; see
// specs/domains/oast/README.md and
// specs/decisions/005-interactsh-oast-backend.md.
type interactshClient struct {
	serverURL string
	domain    string
}

// NewInteractshClient constructs an OAST backed by a self-hosted Interactsh
// server reachable at serverURL with callbacks under the delegated domain.
func NewInteractshClient(serverURL, domain string) OAST {
	return &interactshClient{serverURL: serverURL, domain: domain}
}

func (c *interactshClient) NewInteraction(ctx context.Context, purpose string) (*OASTToken, error) {
	// TODO: register a correlation ID with interactsh-server and return the
	// allocated token; see specs/decisions/005-interactsh-oast-backend.md.
	return nil, ErrNotImplemented
}

func (c *interactshClient) Poll(ctx context.Context, tokenID string, since time.Time) ([]Interaction, error) {
	// TODO: poll interactsh-server, decrypt payloads, and map them to
	// protocol-neutral Interaction records; see specs/domains/oast/README.md.
	return nil, ErrNotImplemented
}

func (c *interactshClient) Close(ctx context.Context, tokenID string) error {
	// TODO: deregister the correlation ID with interactsh-server.
	return ErrNotImplemented
}
