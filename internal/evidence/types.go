// Package evidence parses an untrusted client finding into a canonical,
// validated Finding. It is the trust boundary's front door: prose-only or
// malformed input is rejected here before anything executes. Stdlib only.
package evidence

import (
	"encoding/json"
	"errors"
)

// ErrInvalid marks malformed or insufficient evidence (Invalid verdict).
var ErrInvalid = errors.New("evidence: invalid finding")

// Header is a single request/response header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Request is an exact request, replayed verbatim except for mutation slots.
// Body is the raw wire body (a JSON string), not base64.
type Request struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers []Header `json:"headers,omitempty"`
	Body    string   `json:"body,omitempty"`
}

// Target carries the scope, expected origin, and allowlists that bound a finding.
type Target struct {
	ScopeID        string   `json:"scope_id"`
	ExpectedOrigin string   `json:"expected_origin"`
	AllowedHosts   []string `json:"allowed_hosts"`
	AllowedSchemes []string `json:"allowed_schemes"`
	AllowedPorts   []int    `json:"allowed_ports"`
}

// AuthRef references an auth state by id; raw credentials never appear here.
type AuthRef struct {
	Required    bool   `json:"required"`
	AuthStateID string `json:"auth_state_id,omitempty"`
	Role        string `json:"role,omitempty"`
}

// MutationSlots maps a slot name (e.g. "nonce") to the only position the
// verifier may write (param name, JSON pointer, body field).
type MutationSlots map[string]string

// SideEffects declares whether a finding changes state and how to clean up.
type SideEffects struct {
	StateChanging bool      `json:"state_changing"`
	Cleanup       []Request `json:"cleanup,omitempty"`
}

// Finding is the normalized, validated finding the pipeline operates on.
type Finding struct {
	FindingID   string          `json:"finding_id"`
	Type        string          `json:"type"`
	Target      Target          `json:"target"`
	Auth        AuthRef         `json:"auth"`
	Evidence    json.RawMessage `json:"evidence"`
	Proof       json.RawMessage `json:"proof"`
	Controls    []Request       `json:"controls,omitempty"`
	Mutation    MutationSlots   `json:"mutation_slots,omitempty"`
	SideEffects SideEffects     `json:"side_effects"`
}
