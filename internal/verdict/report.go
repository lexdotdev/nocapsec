package verdict

import (
	"encoding/json"
	"time"
)

// NewReport builds a Report with verdict v.
func NewReport(findingID, typ string, v Verdict) Report {
	return Report{FindingID: findingID, Type: typ, Verdict: v}
}

// Reasoned builds a report with a reason code.
func Reasoned(findingID, typ string, v Verdict, reason string) Report {
	return Report{FindingID: findingID, Type: typ, Verdict: v, Reason: reason}
}

// Proven builds a verified report; proof + policy.
func Proven(findingID, typ, targetOrigin string, proof json.RawMessage, pol PolicySummary) Report {
	return Report{FindingID: findingID, Type: typ, Verdict: Verified, TargetOrigin: targetOrigin, Proof: proof, Policy: pol}
}

// Unproven builds a not_reproduced report.
func Unproven(findingID, typ, targetOrigin string, pol PolicySummary) Report {
	return Report{FindingID: findingID, Type: typ, Verdict: NotReproduced, TargetOrigin: targetOrigin, Policy: pol}
}

// Stamp sets the decision time.
func (r Report) Stamp(t time.Time) Report {
	r.DecidedAt = t
	return r
}
