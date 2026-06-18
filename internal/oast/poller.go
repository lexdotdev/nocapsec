package oast

import (
	"context"
	"time"
)

// Poll drives the worker-oast polling loop for a single token: it queries the
// backend for interactions observed since the given time and returns the
// matching callbacks. Source attribution and proof-rule evaluation happen in
// the validators that consume these interactions.
//
// TODO: implement the poll window, backoff, and token lifecycle; see
// specs/domains/oast/README.md and
// specs/decisions/005-interactsh-oast-backend.md.
func Poll(ctx context.Context, c OAST, tokenID string, since time.Time) ([]Interaction, error) {
	return nil, ErrNotImplemented
}
