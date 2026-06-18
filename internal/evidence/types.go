// Package evidence parses an untrusted, client-authored finding into a
// canonical, validated form that the rest of the pipeline operates on.
//
// It is the only package that turns prose/JSON into a typed Finding. It imports
// only the standard library (and internal/verdict); it never imports execution
// packages. See specs/domains/evidence/README.md and
// specs/contracts/evidence-contract.md.
package evidence

import (
	"encoding/json"
	"errors"
)

// ErrInvalid indicates malformed or insufficient evidence; it maps to the
// Invalid verdict. Wrap it with a stable reason for reporting.
var ErrInvalid = errors.New("evidence: invalid finding")

// Header is a single request/response header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Request is an exact request supplied by the finding. It is replayed verbatim
// except for values filled into declared mutation slots.
type Request struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers []Header `json:"headers,omitempty"`
	Body    []byte   `json:"body,omitempty"`
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

// MutationSlots names the only positions the verifier may write into. The key is
// a logical slot name (e.g. "oast_url", "nonce"); the value is the location
// (parameter name, JSON pointer, body field, etc.).
type MutationSlots map[string]string

// SideEffects declares whether a finding changes state and how to clean up.
type SideEffects struct {
	StateChanging bool      `json:"state_changing"`
	Cleanup       []Request `json:"cleanup,omitempty"`
}

// Finding is the normalized, validated form of a client finding. It is the
// single object the rest of the pipeline operates on.
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
