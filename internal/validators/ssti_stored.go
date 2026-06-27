package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sstiStored struct{}

func (sstiStored) Type() string    { return "ssti.stored" }
func (sstiStored) Cap() Capability { return CapHTTPReplay }

type sstiStoredInput struct {
	ev      sstiStoredEvidence
	control string
	ssti    string
	reps    int
}

func parseStoredSSTIInput(job Job) (sstiStoredInput, bool) {
	var ev sstiStoredEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return sstiStoredInput{}, false
	}
	var proof sstiProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return sstiStoredInput{}, false
	}

	control := ev.Injection.Payloads["control"]
	ssti := ev.Injection.Payloads["ssti"]
	if control == "" || !hasSSTIMarkerSlot(ssti) ||
		!ev.Injection.Location.valid() || !validStoredSSTIRequests(ev) {
		return sstiStoredInput{}, false
	}

	reps := proof.Repetitions
	if reps < 1 {
		reps = 2
	}
	return sstiStoredInput{ev: ev, control: control, ssti: ssti, reps: reps}, true
}

// Validate proves stored SSTI via contrast.
func (sstiStored) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	in, ok := parseStoredSSTIInput(job)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}

	creds, v := loadExtractCreds(ctx, env, job.Finding.Auth)
	if v != "" {
		return Result{Verdict: v}, nil
	}

	defer runCleanup(ctx, env, job.Finding.SideEffects.Cleanup)

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	var lastProduct string
	var lastRedirects []string
	for i := range in.reps {
		expr, product := newComputedMarker()
		controlSetup, err1 := injectValue(in.ev.SetupRequest, in.ev.Injection.Location, replaceSlot(in.control, "ssti_marker", expr))
		candidateSetup, err2 := injectValue(in.ev.SetupRequest, in.ev.Injection.Location, replaceSlot(in.ssti, "ssti_marker", expr))
		if err1 != nil || err2 != nil {
			return Result{Verdict: verdict.Invalid}, nil
		}

		controlHas, _, v, err := replayStoredSSTIArm(ctx, bundle, in.ev, controlSetup, product, creds)
		if v != "" {
			return Result{Verdict: v}, err
		}
		if controlHas {
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			return Result{Verdict: verdict.Inconclusive}, nil
		}

		candidateHas, redirects, v, err := replayStoredSSTIArm(ctx, bundle, in.ev, candidateSetup, product, creds)
		if v != "" {
			return Result{Verdict: v}, err
		}
		if !candidateHas {
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			return Result{Verdict: verdict.Inconclusive}, nil
		}

		lastProduct, lastRedirects = product, redirects
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sstiProofBlock{
			ComputedMarker:        lastProduct,
			Repetitions:           in.reps,
			MarkerInCandidate:     true,
			MarkerAbsentInControl: true,
		}),
		Redirects: lastRedirects,
	}, nil
}

func replayStoredSSTIArm(
	ctx context.Context,
	bundle *httpx.ClientBundle,
	ev sstiStoredEvidence,
	setup evidence.Request,
	product string,
	creds *authstate.Credentials,
) (observed bool, redirects []string, v verdict.Verdict, err error) {
	applyCreds(&setup, creds)
	resp, err := httpx.Replay(ctx, bundle, setup)
	if err != nil {
		return false, nil, verdict.Inconclusive, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return false, nil, verdict.Inconclusive, nil
	}

	for i, trigger := range ev.Trigger {
		applyCreds(&trigger, creds)
		tResp, err := httpx.Replay(ctx, bundle, trigger)
		if err != nil {
			return false, nil, verdict.Inconclusive, fmt.Errorf("ssti.stored: trigger[%d]: %w", i, err)
		}
		if tResp.StatusCode >= http.StatusBadRequest {
			return false, nil, verdict.Inconclusive, nil
		}
	}

	observe := ev.Observe
	applyCreds(&observe, creds)
	resp, err = httpx.Replay(ctx, bundle, observe)
	if err != nil {
		return false, nil, verdict.Inconclusive, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return false, nil, verdict.Inconclusive, nil
	}
	return strings.Contains(string(resp.RespBody), product), formatRedirects(resp.Redirects), "", nil
}

type sstiStoredEvidence struct {
	SetupRequest evidence.Request   `json:"setup_request"`
	Injection    injectionEvidence  `json:"injection"`
	Trigger      []evidence.Request `json:"trigger"`
	Observe      evidence.Request   `json:"observe"`
}

func validStoredSSTIRequests(ev sstiStoredEvidence) bool {
	if ev.SetupRequest.Method == "" || ev.SetupRequest.URL == "" ||
		ev.Observe.Method == "" || ev.Observe.URL == "" ||
		len(ev.Trigger) == 0 {
		return false
	}
	for _, req := range ev.Trigger {
		if req.Method == "" || req.URL == "" {
			return false
		}
	}
	return true
}
