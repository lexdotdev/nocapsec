package verdict

import (
	"encoding/json"
	"time"
)

// NewReport builds a Report with the given verdict; DecidedAt stays zero until
// the caller Stamps it, keeping construction side-effect free.
func NewReport(findingID, typ string, v Verdict) Report {
	return Report{FindingID: findingID, Type: typ, Verdict: v}
}

// Reasoned builds a terminal report carrying a stable reason code. Used for the
// rejected / invalid / inconclusive outcomes, which always explain themselves.
func Reasoned(findingID, typ string, v Verdict, reason string) Report {
	r := NewReport(findingID, typ, v)
	r.Reason = reason
	return r
}

// Proven builds a verified report with its type-specific proof block and the
// policy decisions that backed it.
func Proven(findingID, typ, targetOrigin string, proof json.RawMessage, pol PolicySummary) Report {
	r := NewReport(findingID, typ, Verified)
	r.TargetOrigin = targetOrigin
	r.Proof = proof
	r.Policy = pol
	return r
}

// Unproven builds a not_reproduced report: the validator ran clean but the
// proof did not happen.
func Unproven(findingID, typ, targetOrigin string, pol PolicySummary) Report {
	r := NewReport(findingID, typ, NotReproduced)
	r.TargetOrigin = targetOrigin
	r.Policy = pol
	return r
}

// Proof marshals a typed proof block into the raw form Report.Proof carries.
func Proof(v any) (json.RawMessage, error) {
	return json.Marshal(v)
}

// Stamp sets the decision time and returns the report.
func (r Report) Stamp(t time.Time) Report {
	r.DecidedAt = t
	return r
}

// JSON marshals the report to its canonical JSON encoding.
func (r Report) JSON() ([]byte, error) {
	return json.Marshal(r)
}
