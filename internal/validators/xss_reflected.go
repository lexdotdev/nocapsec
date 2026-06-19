package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

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

	// Inject the per-run nonce so the reflected payload carries it.
	ev.Entrypoint.URL = replaceNonceSlot(ev.Entrypoint.URL, job.Nonce)

	// Reject disallowed initial-navigation schemes.
	entryURL := ev.Entrypoint.URL
	if rejectScheme(entryURL) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	// Policy-check the entrypoint URL.
	safe, err := env.Policy.CheckURL(entryURL, policy.PhaseInitial)
	if err != nil {
		return Result{Verdict: verdict.Rejected}, nil //nolint:nilerr // policy rejection -> rejected
	}

	// Initial navigation origin must equal target origin.
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

	result, err := env.Browser.Run(ctx, browser.BrowserJob{
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

	// Reject if page navigated to an external origin before any signal.
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

type xssProofBlock struct {
	Signal               string `json:"signal"`
	ExecutionOrigin      string `json:"execution_origin"`
	MessageContainsNonce bool   `json:"message_contains_nonce"`
}

// xssReflectedEvidence is the evidence shape for xss.reflected.
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

// xssProof is shared between reflected and stored XSS.
type xssProof struct {
	AcceptedSignals         []string `json:"accepted_signals"`
	ExpectedMessageContains string   `json:"expected_message_contains"`
	ExpectedExecutionOrigin string   `json:"expected_execution_origin"`
	AllowIframeExecution    bool     `json:"allow_iframe_execution"`
	TimeoutMS               int      `json:"timeout_ms"`
}

// rejectScheme returns true for schemes that must never be treated as XSS proof.
func rejectScheme(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return false
	default:
		return true
	}
}

// navigatedExternal checks if any committed navigation went to an origin
// other than the target before signals could fire.
func navigatedExternal(navs []browser.NavEvent, target policy.Origin) bool {
	for _, n := range navs {
		o, ok := policy.ParseOrigin(n.Origin)
		if !ok {
			continue
		}
		if !o.Equal(target) {
			return true
		}
	}
	return false
}

// qualifyingSignal returns the matched signal kind if any dialog or console
// event satisfies the proof rule: carries the nonce, from the target origin,
// not from the verifier hook.
func qualifyingSignal(r browser.BrowserResult, pf xssProof, target policy.Origin, nonce string) (string, bool) {
	for _, sig := range pf.AcceptedSignals {
		switch sig {
		case "javascript_dialog":
			for _, d := range r.Dialogs {
				if d.FromVerifierHook {
					continue
				}
				if !strings.Contains(d.Message, nonce) {
					continue
				}
				o, ok := policy.ParseOrigin(d.SourceOrigin)
				if !ok || !o.Equal(target) {
					continue
				}
				return sig, true
			}
		case "console_log":
			for _, c := range r.Console {
				if !strings.Contains(c.Text, nonce) {
					continue
				}
				if !consoleOriginMatch(c.SourceURL, target) {
					continue
				}
				return sig, true
			}
		}
	}
	return "", false
}

// consoleOriginMatch checks that a console event's source URL belongs to the
// target origin. Empty/missing source URLs are rejected.
func consoleOriginMatch(sourceURL string, target policy.Origin) bool {
	if sourceURL == "" {
		return false
	}
	u, err := url.Parse(sourceURL)
	if err != nil || u.Host == "" {
		return false
	}
	o, ok := policy.ParseOrigin(u.Scheme + "://" + u.Host)
	if !ok {
		return false
	}
	return o.Equal(target)
}

func init() { Register(xssReflected{}) }
