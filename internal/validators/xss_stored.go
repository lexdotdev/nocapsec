package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xssStored struct{}

func (xssStored) Type() string    { return "xss.stored" }
func (xssStored) Cap() Capability { return CapBrowser }

func (xssStored) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev xssStoredEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil
	}
	var pf xssProof
	if err := json.Unmarshal(job.Finding.Proof, &pf); err != nil {
		return Result{Verdict: verdict.Invalid}, nil
	}

	targetOrigin, ok := policy.ParseOrigin(pf.ExpectedExecutionOrigin)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	if env.Browser == nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	// Inject the per-run nonce so the stored payload carries it.
	for i := range ev.Setup {
		ev.Setup[i].URL = strings.ReplaceAll(ev.Setup[i].URL, "{{nonce}}", job.Nonce)
		ev.Setup[i].Body = strings.ReplaceAll(ev.Setup[i].Body, "{{nonce}}", job.Nonce)
	}

	// Run cleanup on all exit paths.
	defer runCleanup(ctx, env, ev.Cleanup)

	// Phase 1: store the payload via setup requests.
	if res, err := runSetup(ctx, env, ev.Setup); res.Verdict != "" {
		return res, err
	}

	// Phase 2: trigger in a fresh browser context.
	triggerURL := ev.Trigger.URL
	if rejectScheme(triggerURL) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	safe, err := env.Policy.CheckURL(triggerURL, policy.PhaseInitial)
	if err != nil {
		return Result{Verdict: verdict.Rejected}, nil
	}
	if !safe.Origin.Equal(targetOrigin) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	timeout := pf.TimeoutMS
	if timeout <= 0 {
		timeout = 10000
	}

	result, err := env.Browser.Run(ctx, browser.BrowserJob{
		Entrypoint:    ev.Trigger,
		AuthStateID:   job.Finding.Auth.AuthStateID,
		WaitMode:      "load_or_network_idle",
		TimeoutMS:     timeout,
		AcceptSignals: pf.AcceptedSignals,
	})
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, fmt.Errorf("xss.stored: browser: %w", err)
	}

	if navigatedExternal(result.Navigation, targetOrigin) {
		return Result{Verdict: verdict.NotReproduced}, nil
	}

	if signal, ok := qualifyingSignal(result, pf, targetOrigin, job.Nonce); ok {
		return Result{Verdict: verdict.Verified, Proof: proofJSON(xssProofBlock{
			Signal:               signal,
			ExecutionOrigin:      targetOrigin.String(),
			MessageContainsNonce: true,
		})}, nil
	}
	return Result{Verdict: verdict.NotReproduced}, nil
}

type xssStoredEvidence struct {
	Setup         []evidence.Request `json:"setup"`
	Trigger       evidence.Request   `json:"trigger"`
	VulnParam     string             `json:"vulnerable_parameter"`
	PayloadMarker string             `json:"payload_marker"`
	Cleanup       []evidence.Request `json:"cleanup,omitempty"`
}

// runSetup replays setup requests. Returns a non-empty verdict on failure,
// the zero Result on success.
func runSetup(ctx context.Context, env Env, reqs []evidence.Request) (Result, error) {
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout
	for i, req := range reqs {
		if _, pErr := env.Policy.CheckURL(req.URL, policy.PhaseInitial); pErr != nil {
			return Result{Verdict: verdict.Rejected}, nil //nolint:nilerr // policy rejection -> rejected verdict, not an operational error
		}
		capture, err := httpx.Replay(ctx, bundle, req)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, fmt.Errorf("xss.stored: setup[%d]: %w", i, err)
		}
		if capture.StatusCode >= http.StatusInternalServerError {
			return Result{Verdict: verdict.Inconclusive}, fmt.Errorf("xss.stored: setup[%d] status %d", i, capture.StatusCode)
		}
	}
	return Result{}, nil
}

// runCleanup replays cleanup requests; failures never change the verdict.
func runCleanup(ctx context.Context, env Env, reqs []evidence.Request) {
	if len(reqs) == 0 {
		return
	}
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout
	for _, req := range reqs {
		_, _ = httpx.Replay(ctx, bundle, req)
	}
}

func init() { Register(xssStored{}) }
