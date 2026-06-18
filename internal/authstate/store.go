// Package authstate models auth as a first-class encrypted object referenced
// only by auth_state_id. It loads auth state, runs a pre-validation
// healthcheck, injects credentials into a job's allowed origins, and redacts
// secrets from stored artifacts.
package authstate

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by unimplemented stubs.
var ErrNotImplemented = errors.New("authstate: not implemented")

// Healthcheck probes that a session is still valid before a verification run.
type Healthcheck struct {
	Method               string
	URL                  string
	ExpectedStatus       int
	ExpectedBodyContains string
}

// AuthState is referenced from a finding only by ID. Raw secrets (cookies,
// tokens, Authorization headers) live encrypted elsewhere, never in this struct.
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
// TODO: back with the encrypted at-rest store keyed on encryption_key_ref.
type memStore struct{}

// Get returns the auth state for id.
//
// TODO: implement encrypted lookup.
func (memStore) Get(context.Context, string) (*AuthState, error) {
	return nil, ErrNotImplemented
}

// NewStore returns a Store backed by the (stub) in-memory implementation.
func NewStore() Store {
	return memStore{}
}
