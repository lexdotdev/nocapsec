package validators

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type nosqliAuthBypass struct{}

func (nosqliAuthBypass) Type() string    { return "nosqli.auth_bypass" }
func (nosqliAuthBypass) Cap() Capability { return CapHTTPReplay }

// Validate proves NoSQL operator auth bypass.
func (nosqliAuthBypass) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	arms, marker, reps, v := prepareNoSQLi(job)
	if v != "" {
		return Result{Verdict: v}, nil
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	// operator arm logs in; control does not.
	redirects, v, err := stableContrast(ctx, bundle, arms.candidate, arms.control, marker, reps)
	if v != "" {
		return Result{Verdict: v}, err
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(nosqliAuthBypassProofBlock{
			SuccessMarker:         marker,
			Repetitions:           reps,
			MarkerInCandidate:     true,
			MarkerAbsentInControl: true,
		}),
		Redirects: redirects,
	}, nil
}

// nosqliArms holds the two request arms.
type nosqliArms struct {
	candidate evidence.Request
	control   evidence.Request
}

// prepareNoSQLi decodes and builds the arms.
// Non-empty verdict means stop (Invalid).
func prepareNoSQLi(job Job) (arms nosqliArms, marker string, reps int, v verdict.Verdict) {
	var ev sqliBooleanEvidence // base_request + injection
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return arms, "", 0, verdict.Invalid
	}
	var proof nosqliAuthBypassProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return arms, "", 0, verdict.Invalid
	}

	candidate, okC := ev.Injection.Payloads["candidate"]
	control, okT := ev.Injection.Payloads["control"]
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" ||
		!ev.Injection.Location.valid() || !okC || !okT || proof.SuccessMarker == "" {
		return arms, "", 0, verdict.Invalid
	}

	candReq, err1 := injectValue(ev.BaseRequest, ev.Injection.Location, candidate)
	ctlReq, err2 := injectValue(ev.BaseRequest, ev.Injection.Location, control)
	if err1 != nil || err2 != nil {
		return arms, "", 0, verdict.Invalid
	}
	// guard: DB marker must not be in the request.
	if strings.Contains(candReq.Body, proof.SuccessMarker) || strings.Contains(candReq.URL, proof.SuccessMarker) {
		return arms, "", 0, verdict.Invalid
	}

	reps = proof.Repetitions
	if reps < 1 {
		reps = 2
	}
	return nosqliArms{candidate: candReq, control: ctlReq}, proof.SuccessMarker, reps, ""
}

type nosqliAuthBypassProof struct {
	SuccessMarker string `json:"success_marker"`
	Repetitions   int    `json:"repetitions"`
}

type nosqliAuthBypassProofBlock struct {
	SuccessMarker         string `json:"success_marker"`
	Repetitions           int    `json:"repetitions"`
	MarkerInCandidate     bool   `json:"marker_in_candidate"`
	MarkerAbsentInControl bool   `json:"marker_absent_in_control"`
}
