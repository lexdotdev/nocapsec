package validators

import (
	"context"
	"encoding/json"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sstiReflected struct{}

func (sstiReflected) Type() string    { return "ssti.reflected" }
func (sstiReflected) Cap() Capability { return CapHTTPReplay }

// Validate proves reflected SSTI via contrast.
func (sstiReflected) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev sqliBooleanEvidence // base_request + injection
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}
	var proof sstiProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}

	control, okC := ev.Injection.Payloads["control"]
	ssti, okS := ev.Injection.Payloads["ssti"]
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" ||
		!ev.Injection.Location.valid() || !okC || !okS || !hasSSTIMarkerSlot(ssti) {
		return Result{Verdict: verdict.Invalid}, nil
	}

	res, err := verifyComputedMarker(ctx, env, ev.BaseRequest, ev.Injection.Location, control, ssti, "ssti_marker", proof.Repetitions)
	if res.verdict != verdict.Verified {
		return Result{Verdict: res.verdict}, err
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sstiProofBlock{
			ComputedMarker:        res.product,
			Repetitions:           res.reps,
			MarkerInCandidate:     true,
			MarkerAbsentInControl: true,
		}),
		Redirects: res.redirects,
	}, nil
}

type sstiProof struct {
	ExpectedMarkerInCandidate     bool `json:"expected_marker_in_candidate"`
	ExpectedMarkerAbsentInControl bool `json:"expected_marker_absent_in_control"`
	Repetitions                   int  `json:"repetitions"`
}

type sstiProofBlock struct {
	ComputedMarker        string `json:"computed_marker"`
	Repetitions           int    `json:"repetitions"`
	MarkerInCandidate     bool   `json:"marker_in_candidate"`
	MarkerAbsentInControl bool   `json:"marker_absent_in_control"`
}
