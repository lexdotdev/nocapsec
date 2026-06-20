// Package verdict defines the closed set + report.
package verdict

import (
	"encoding/json"
	"time"
)

// Verdict is one of a closed set.
type Verdict string

const (
	// Verified: the proof rule was satisfied.
	Verified Verdict = "verified"
	// NotReproduced: ran cleanly but no proof.
	NotReproduced Verdict = "not_reproduced"
	// Inconclusive: timeout, auth expiry, instability.
	Inconclusive Verdict = "inconclusive"
	// Rejected: policy violation.
	Rejected Verdict = "rejected"
	// Invalid: malformed evidence or no validator.
	Invalid Verdict = "invalid"
)

// Valid reports whether v is in the closed set.
func (v Verdict) Valid() bool {
	switch v {
	case Verified, NotReproduced, Inconclusive, Rejected, Invalid:
		return true
	default:
		return false
	}
}

// PolicySummary records a verdict's decisions.
type PolicySummary struct {
	SchemeOK            bool     `json:"scheme_ok"`
	InitialOriginPinned bool     `json:"initial_origin_pinned"`
	FinalOriginOK       bool     `json:"final_origin_ok"`
	Redirects           []string `json:"redirects"`
}

// ArtifactRefs maps artifact name to stored ref.
type ArtifactRefs map[string]string

// Report is the reproducible record for a finding.
type Report struct {
	FindingID    string          `json:"finding_id"`
	Type         string          `json:"type"`
	Verdict      Verdict         `json:"verdict"`
	TargetOrigin string          `json:"target_origin,omitempty"`
	Proof        json.RawMessage `json:"proof,omitempty"`
	Policy       PolicySummary   `json:"policy"`
	Artifacts    ArtifactRefs    `json:"artifacts,omitempty"`
	DecidedAt    time.Time       `json:"decided_at"`
	// Reason: stable code for non-verified verdicts.
	Reason string `json:"reason,omitempty"`
}
