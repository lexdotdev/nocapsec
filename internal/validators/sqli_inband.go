package validators

import (
	"context"
	"encoding/json"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sqliInband struct{}

func (sqliInband) Type() string    { return "sqli.inband" }
func (sqliInband) Cap() Capability { return CapHTTPReplay }

func (sqliInband) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, proof, ok := decodeInband(job)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	control, inband, ok := inbandPayloads(ev)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}

	res, err := verifyComputedMarker(ctx, env, ev.BaseRequest, ev.Injection.Location, control, inband, "sqli_marker", proof.Repetitions)
	if res.verdict != verdict.Verified {
		return Result{Verdict: res.verdict}, err
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sqliInbandProofBlock{
			ComputedMarker:        res.product,
			Repetitions:           res.reps,
			MarkerInInband:        true,
			MarkerAbsentInControl: true,
		}),
		Redirects: res.redirects,
	}, nil
}

// decodeInband unmarshals evidence + proof.
func decodeInband(job Job) (sqliBooleanEvidence, sqliInbandProof, bool) {
	var ev sqliBooleanEvidence // same shape: base_request + injection
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return ev, sqliInbandProof{}, false
	}
	var proof sqliInbandProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return ev, proof, false
	}
	return ev, proof, true
}

// inbandPayloads returns control/inband values.
func inbandPayloads(ev sqliBooleanEvidence) (control, inband string, ok bool) {
	control, okC := ev.Injection.Payloads["control"]
	inband, okI := ev.Injection.Payloads["inband"]
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" ||
		!ev.Injection.Location.valid() || !okC || !okI || !hasMarkerSlot(inband) {
		return "", "", false
	}
	return control, inband, true
}

type sqliInbandProof struct {
	ExpectedMarkerInInband        bool `json:"expected_marker_in_inband"`
	ExpectedMarkerAbsentInControl bool `json:"expected_marker_absent_in_control"`
	Repetitions                   int  `json:"repetitions"`
}

type sqliInbandProofBlock struct {
	ComputedMarker        string `json:"computed_marker"`
	Repetitions           int    `json:"repetitions"`
	MarkerInInband        bool   `json:"marker_in_inband"`
	MarkerAbsentInControl bool   `json:"marker_absent_in_control"`
}

func init() { Register(sqliInband{}) }
