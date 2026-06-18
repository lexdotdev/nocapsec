// Package authstate models authentication as a first-class, encrypted object
// referenced only by auth_state_id. It loads auth state, runs a pre-validation
// healthcheck, injects credentials into the exact allowed origins for a job,
// and redacts secrets from every stored artifact.
//
// See specs/domains/authstate/README.md and
// specs/decisions/007-auth-state-first-class.md.
package authstate

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is the sentinel returned by unimplemented stubs.
var ErrNotImplemented = errors.New("authstate: not implemented")

// Healthcheck describes a pre-validation probe used to confirm a session is
// still valid before spending a verification run.
type Healthcheck struct {
	Method               string
	URL                  string
	ExpectedStatus       int
	ExpectedBodyContains string
}

// AuthState is a first-class authentication object referenced from a finding
// only by ID. Raw secret material (cookies, tokens, Authorization headers) is
// stored separately and encrypted, and never appears in this struct.
type AuthState struct {
	ID             string
	Kind           string   // e.g. "browser_storage_bundle", "http_cookie_jar"
	AllowedOrigins []string // exact origins the state may be injected into
	Role           string
	ExpiresAt      time.Time
	Contains       []string // {"cookies","localStorage","sessionStorage"}
	Healthcheck    Healthcheck
}

// Store looks up auth state by its opaque auth_state_id.
type Store interface {
	Get(ctx context.Context, id string) (*AuthState, error)
}

// memStore is a stub in-memory Store.
//
// TODO: back this with the encrypted at-rest store keyed on
// authstate.encryption_key_ref per specs/domains/authstate/README.md and
// specs/decisions/007-auth-state-first-class.md.
type memStore struct{}

// Get returns the auth state for id.
//
// TODO: implement encrypted lookup per specs/domains/authstate/README.md.
func (memStore) Get(ctx context.Context, id string) (*AuthState, error) {
	return nil, ErrNotImplemented
}

// NewStore returns a Store backed by the (stub) in-memory implementation.
func NewStore() Store {
	return memStore{}
}
