// Package evidence: canonical, validated Findings.
package evidence

import (
	"encoding/json"
	"errors"
)

// ErrInvalid marks malformed/insufficient evidence.
var ErrInvalid = errors.New("evidence: invalid finding")

// Header is a single request/response header.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Request: replayed verbatim except slots.
// Body is raw wire, not base64.
type Request struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers []Header `json:"headers,omitempty"`
	Body    string   `json:"body,omitempty"`
}

// Target: origin + allowlists bounding a finding.
type Target struct {
	ExpectedOrigin string   `json:"expected_origin"`
	AllowedHosts   []string `json:"allowed_hosts"`
	AllowedSchemes []string `json:"allowed_schemes"`
	AllowedPorts   []int    `json:"allowed_ports"`
}

// AuthRef references auth by id.
// Raw credentials never appear.
type AuthRef struct {
	Required    bool   `json:"required"`
	AuthStateID string `json:"auth_state_id,omitempty"`
	Role        string `json:"role,omitempty"`
}

// MutationSlots: slot -> only position
// the verifier may write.
type MutationSlots map[string]string

// SideEffects declares cleanup for a finding
// that changes state.
type SideEffects struct {
	Cleanup []Request `json:"cleanup,omitempty"`
}

// Finding is the validated finding to run.
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
