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

// Validate proves stored SSTI via contrast.
func (sstiStored) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev sstiStoredEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}
	var proof sstiProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}

	control, okC := ev.Injection.Payloads["control"]
	ssti, okS := ev.Injection.Payloads["ssti"]
	if ev.SetupRequest.Method == "" || ev.SetupRequest.URL == "" ||
		ev.Observe.Method == "" || ev.Observe.URL == "" ||
		len(ev.Trigger) == 0 || !ev.Injection.Location.valid() ||
		!okC || !okS || !hasSSTIMarkerSlot(ssti) {
		return Result{Verdict: verdict.Invalid}, nil
	}
	for _, req := range ev.Trigger {
		if req.Method == "" || req.URL == "" {
			return Result{Verdict: verdict.Invalid}, nil
		}
	}

	creds, v := loadExtractCreds(ctx, env, job.Finding.Auth)
	if v != "" {
		return Result{Verdict: v}, nil
	}

	defer runCleanup(ctx, env, job.Finding.SideEffects.Cleanup)

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout
	reps := proof.Repetitions
	if reps < 1 {
		reps = 2
	}

	var lastProduct string
	var lastRedirects []string
	for i := range reps {
		expr, product := newComputedMarker()
		controlSetup, err1 := injectValue(ev.SetupRequest, ev.Injection.Location, replaceSlot(control, "ssti_marker", expr))
		candidateSetup, err2 := injectValue(ev.SetupRequest, ev.Injection.Location, replaceSlot(ssti, "ssti_marker", expr))
		if err1 != nil || err2 != nil {
			return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // bad injection slot -> invalid
		}

		controlHas, _, v, err := replayStoredSSTIArm(ctx, bundle, ev, controlSetup, product, creds)
		if v != "" {
			return Result{Verdict: v}, err
		}
		if controlHas {
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			return Result{Verdict: verdict.Inconclusive}, nil
		}

		candidateHas, redirects, v, err := replayStoredSSTIArm(ctx, bundle, ev, candidateSetup, product, creds)
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
			Repetitions:           reps,
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
	cap, err := httpx.Replay(ctx, bundle, setup)
	if err != nil {
		return false, nil, verdict.Inconclusive, err
	}
	if cap.StatusCode >= http.StatusBadRequest {
		return false, nil, verdict.Inconclusive, nil
	}

	for i, trigger := range ev.Trigger {
		applyCreds(&trigger, creds)
		cap, err := httpx.Replay(ctx, bundle, trigger)
		if err != nil {
			return false, nil, verdict.Inconclusive, fmt.Errorf("ssti.stored: trigger[%d]: %w", i, err)
		}
		if cap.StatusCode >= http.StatusBadRequest {
			return false, nil, verdict.Inconclusive, nil
		}
	}

	observe := ev.Observe
	applyCreds(&observe, creds)
	cap, err = httpx.Replay(ctx, bundle, observe)
	if err != nil {
		return false, nil, verdict.Inconclusive, err
	}
	if cap.StatusCode >= http.StatusBadRequest {
		return false, nil, verdict.Inconclusive, nil
	}
	return strings.Contains(string(cap.RespBody), product), formatRedirects(cap.Redirects), "", nil
}

type sstiStoredEvidence struct {
	SetupRequest evidence.Request   `json:"setup_request"`
	Injection    injectionEvidence  `json:"injection"`
	Trigger      []evidence.Request `json:"trigger"`
	Observe      evidence.Request   `json:"observe"`
}

func init() { Register(sstiStored{}) }
