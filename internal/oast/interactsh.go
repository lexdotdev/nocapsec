package oast

import (
	"context"
	"time"
)

// interactshClient is the Interactsh-backed OAST. Interactsh specifics
// (registration, polling secrets, AES payloads) stay confined to this file.
//
// TODO: implement against a self-hosted interactsh-server.
type interactshClient struct {
	serverURL string
	domain    string
}

// NewInteractshClient constructs an OAST backed by a self-hosted Interactsh
// server reachable at serverURL with callbacks under the delegated domain.
func NewInteractshClient(serverURL, domain string) OAST {
	return &interactshClient{serverURL: serverURL, domain: domain}
}

func (c *interactshClient) NewInteraction(context.Context, string) (*OASTToken, error) {
	// TODO: register a correlation ID and return the allocated token.
	return nil, ErrNotImplemented
}

func (c *interactshClient) Poll(context.Context, string, time.Time) ([]Interaction, error) {
	// TODO: poll, decrypt payloads, map to protocol-neutral Interactions.
	return nil, ErrNotImplemented
}

func (c *interactshClient) Close(context.Context, string) error {
	// TODO: deregister the correlation ID with interactsh-server.
	return ErrNotImplemented
}
