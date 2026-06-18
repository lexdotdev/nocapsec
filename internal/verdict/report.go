package verdict

import "encoding/json"

// NewReport constructs a Report for a finding with the given verdict.
//
// DecidedAt is intentionally left as the zero time; the caller stamps it when
// the decision is finalized so that construction stays side-effect free and
// testable. See specs/domains/verdict/README.md.
func NewReport(findingID, typ string, v Verdict) Report {
	return Report{
		FindingID: findingID,
		Type:      typ,
		Verdict:   v,
	}
}

// JSON marshals the report to its canonical JSON encoding.
//
// See specs/domains/verdict/README.md.
func (r Report) JSON() ([]byte, error) {
	return json.Marshal(r)
}
