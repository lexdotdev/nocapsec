package validators

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xssReflected struct{}

func (xssReflected) Type() string    { return "xss.reflected" }
func (xssReflected) Cap() Capability { return CapBrowser }

func (xssReflected) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev xssReflectedEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}
	var pf xssProof
	if err := json.Unmarshal(job.Finding.Proof, &pf); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}

	targetOrigin, ok := policy.ParseOrigin(pf.ExpectedExecutionOrigin)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	if env.Browser == nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	// Inject per-run nonce into the reflected payload.
	ev.Entrypoint.URL = replaceNonceSlot(ev.Entrypoint.URL, job.Nonce)

	// Reject disallowed initial-navigation schemes.
	entryURL := ev.Entrypoint.URL
	if rejectScheme(entryURL) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	// Policy-check the entrypoint.
	safe, err := env.Policy.CheckURL(entryURL, policy.PhaseInitial)
	if err != nil {
		return Result{Verdict: verdict.Rejected}, nil //nolint:nilerr // policy rejection -> rejected
	}

	// Initial origin must be the target.
	if !safe.Origin.Equal(targetOrigin) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	timeout := pf.TimeoutMS
	if timeout <= 0 {
		timeout = 7000
	}

	postLoad := make([]browser.Action, len(ev.Trigger.PostLoadActions))
	for i, n := range ev.Trigger.PostLoadActions {
		postLoad[i] = browser.Action{Kind: n}
	}

	result, err := runBrowser(ctx, job, env, browser.BrowserJob{
		Entrypoint:    ev.Entrypoint,
		AuthStateID:   job.Finding.Auth.AuthStateID,
		PostLoad:      postLoad,
		WaitMode:      ev.Trigger.Wait,
		TimeoutMS:     timeout,
		AcceptSignals: pf.AcceptedSignals,
	})
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, fmt.Errorf("xss.reflected: browser: %w", err)
	}

	return xssVerdict(result, pf, targetOrigin, job.Nonce), nil
}

// xssReflectedEvidence is the xss.reflected shape.
type xssReflectedEvidence struct {
	Entrypoint    evidence.Request    `json:"entrypoint"`
	PayloadMarker string              `json:"payload_marker"`
	Trigger       xssReflectedTrigger `json:"trigger"`
}

type xssReflectedTrigger struct {
	Kind            string   `json:"kind"`
	Wait            string   `json:"wait"`
	PostLoadActions []string `json:"post_load_actions"`
}
