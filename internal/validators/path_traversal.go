package validators

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type pathTraversal struct{}

func (pathTraversal) Type() string    { return "path_traversal.file_read" }
func (pathTraversal) Cap() Capability { return CapHTTPReplay }

// Validate proves file read contrast.
func (pathTraversal) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	arms, marker, reps, ok := preparePathTraversal(job)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	// traversal leaks marker; control does not.
	redirects, v, err := stableContrast(ctx, bundle, arms.candidate, arms.control, marker, reps)
	if v != "" {
		return Result{Verdict: v}, err
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(pathTraversalProofBlock{
			MatchedMarker:         marker,
			Repetitions:           reps,
			MarkerInCandidate:     true,
			MarkerAbsentInControl: true,
		}),
		Redirects: redirects,
	}, nil
}

// pathTraversalArms: the two request arms.
type pathTraversalArms struct {
	candidate evidence.Request
	control   evidence.Request
}

// preparePathTraversal builds arms.
func preparePathTraversal(job Job) (arms pathTraversalArms, marker string, reps int, ok bool) {
	var ev pathTraversalEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return arms, "", 0, false
	}
	var proof pathTraversalProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return arms, "", 0, false
	}

	candidate, okC := ev.Injection.Payloads["candidate"]
	control, okCtl := ev.Injection.Payloads["control"]
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" ||
		!ev.Injection.Location.valid() || !okC || !okCtl || proof.ExpectedMarker == "" {
		return arms, "", 0, false
	}

	candReq, err1 := injectValue(ev.BaseRequest, ev.Injection.Location, candidate)
	ctlReq, err2 := injectValue(ev.BaseRequest, ev.Injection.Location, control)
	if err1 != nil || err2 != nil {
		return arms, "", 0, false
	}
	// Marker must not be reflected.
	if markerReflectable(candidate, proof.ExpectedMarker) ||
		markerReflectable(control, proof.ExpectedMarker) {
		return arms, "", 0, false
	}

	reps = proof.Repetitions
	if reps < 1 {
		reps = 2
	}
	return pathTraversalArms{candidate: candReq, control: ctlReq}, proof.ExpectedMarker, reps, true
}

// markerReflectable detects reflection.
func markerReflectable(payload, marker string) bool {
	for range 5 {
		if strings.Contains(payload, marker) {
			return true
		}
		dec, err := url.QueryUnescape(payload)
		if err != nil || dec == payload {
			break
		}
		payload = dec
	}
	return false
}

type pathTraversalEvidence struct {
	BaseRequest evidence.Request  `json:"base_request"`
	Injection   injectionEvidence `json:"injection"`
}

type pathTraversalProof struct {
	ExpectedMarker string `json:"expected_marker"`
	Repetitions    int    `json:"repetitions"`
}

type pathTraversalProofBlock struct {
	MatchedMarker         string `json:"matched_marker"`
	Repetitions           int    `json:"repetitions"`
	MarkerInCandidate     bool   `json:"marker_in_candidate"`
	MarkerAbsentInControl bool   `json:"marker_absent_in_control"`
}
