// Package verdict defines the closed set of verification outcomes and the
// reproducible report that accompanies each one.
package verdict

import (
	"encoding/json"
	"time"
)

// Verdict is one of a closed set of verification outcomes. No other value is
// valid; operational failures map to Inconclusive and bad input to Invalid.
type Verdict string

const (
	// Verified means the proof rule was satisfied: all numbered conditions held.
	Verified Verdict = "verified"
	// NotReproduced means the validator ran cleanly but the proof did not happen.
	NotReproduced Verdict = "not_reproduced"
	// Inconclusive means a timeout, auth expiry, instability, or missing control
	// signal prevented a verdict.
	Inconclusive Verdict = "inconclusive"
	// Rejected means a policy violation: out-of-scope host, bad scheme, unsafe
	// redirect, blocked IP, etc.
	Rejected Verdict = "rejected"
	// Invalid means malformed or insufficient evidence, or no validator for the type.
	Invalid Verdict = "invalid"
)

// Valid reports whether v is one of the five closed verdict values.
func (v Verdict) Valid() bool {
	switch v {
	case Verified, NotReproduced, Inconclusive, Rejected, Invalid:
		return true
	default:
		return false
	}
}

// PolicySummary records the policy decisions that contributed to a verdict.
type PolicySummary struct {
	SchemeOK            bool     `json:"scheme_ok"`
	InitialOriginPinned bool     `json:"initial_origin_pinned"`
	FinalOriginOK       bool     `json:"final_origin_ok"`
	Redirects           []string `json:"redirects"`
}

// ArtifactRefs maps an artifact name to its stored reference (e.g. artifact://...).
type ArtifactRefs map[string]string

// Report is the boring, reproducible record returned for a finding.
type Report struct {
	FindingID    string          `json:"finding_id"`
	Type         string          `json:"type"`
	Verdict      Verdict         `json:"verdict"`
	TargetOrigin string          `json:"target_origin,omitempty"`
	Proof        json.RawMessage `json:"proof,omitempty"`
	Policy       PolicySummary   `json:"policy"`
	Artifacts    ArtifactRefs    `json:"artifacts,omitempty"`
	DecidedAt    time.Time       `json:"decided_at"`
	// Reason carries a stable code for rejected/invalid/inconclusive verdicts.
	Reason string `json:"reason,omitempty"`
}
