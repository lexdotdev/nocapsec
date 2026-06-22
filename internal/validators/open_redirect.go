package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type openRedirect struct{}

func (openRedirect) Type() string    { return "open_redirect" }
func (openRedirect) Cap() Capability { return CapBrowser }

func (openRedirect) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev redirectEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil
	}
	var pf redirectProof
	if err := json.Unmarshal(job.Finding.Proof, &pf); err != nil {
		return Result{Verdict: verdict.Invalid}, nil
	}

	targetOrigin, ok := policy.ParseOrigin(ev.ExpectedInitialOrigin)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	if rejectScheme(ev.Entrypoint.URL) {
		return Result{Verdict: verdict.Rejected}, nil
	}
	if env.OAST == nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}
	if !hasOpenRedirectOASTSlot(ev.Entrypoint.URL) {
		return Result{Verdict: verdict.Invalid}, nil
	}

	tok, err := env.OAST.NewInteraction(ctx, "open_redirect")
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}
	defer env.OAST.Close(ctx, tok.CorrelationID) //nolint:errcheck // best-effort

	externalOrigin, ok := originFromRawURL(tok.URLHTTP)
	if !ok {
		return Result{Verdict: verdict.Inconclusive}, nil
	}
	if env.Browser == nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	ev.Entrypoint.URL = injectOpenRedirectSlots(ev.Entrypoint.URL, tok, job.Nonce)

	safe, err := env.Policy.CheckURL(ev.Entrypoint.URL, policy.PhaseBrowserNav)
	if err != nil {
		return Result{Verdict: verdict.Rejected}, nil
	}

	// Initial origin must be the target.
	if !safe.Origin.Equal(targetOrigin) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	timeout := pf.TimeoutMS
	if timeout <= 0 {
		timeout = 8000
	}

	maxHops := ev.MaxHops
	if maxHops <= 0 {
		maxHops = 5
	}

	proxyJob := job
	proxyJob.BrowserAllowedOrigins = append(proxyJob.BrowserAllowedOrigins, externalOrigin)

	result, err := runBrowser(ctx, proxyJob, env, browser.BrowserJob{
		Entrypoint:  ev.Entrypoint,
		AuthStateID: job.Finding.Auth.AuthStateID,
		WaitMode:    "load_or_network_idle",
		TimeoutMS:   timeout,
	})
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, fmt.Errorf("open_redirect: browser: %w", err)
	}

	return evaluateRedirect(result, targetOrigin, externalOrigin, job.Nonce, maxHops), nil
}

func injectOpenRedirectSlots(raw string, tok *oast.OASTToken, nonce string) string {
	raw = replaceSlot(raw, "oast_url", tok.URLHTTP)
	raw = replaceSlot(raw, "oast_host", oastHost(tok))
	return replaceNonceSlot(raw, nonce)
}

func hasOpenRedirectOASTSlot(raw string) bool {
	return hasSlot(raw, "oast_url") || hasSlot(raw, "oast_host")
}

func oastHost(tok *oast.OASTToken) string {
	u, err := url.Parse(tok.URLHTTP)
	if err != nil {
		return tok.Domain
	}
	return u.Host
}

// evaluateRedirect applies the proof rule.
func evaluateRedirect(
	r browser.BrowserResult,
	target, external policy.Origin,
	nonce string, maxHops int,
) Result {
	if len(r.Navigation) == 0 && len(r.Network) == 0 {
		return Result{Verdict: verdict.NotReproduced}
	}

	if !startsAtTarget(r, target) {
		return Result{Verdict: verdict.NotReproduced}
	}

	// Final scheme must be http(s).
	if rejectScheme(r.FinalURL) {
		return Result{Verdict: verdict.Rejected}
	}

	// Final origin must be the declared external one.
	u, err := url.Parse(r.FinalURL)
	if err != nil || u.Host == "" {
		return Result{Verdict: verdict.NotReproduced}
	}
	finalOrigin, ok := policy.ParseOrigin(u.Scheme + "://" + u.Host)
	if !ok || !finalOrigin.Equal(external) {
		return Result{Verdict: verdict.NotReproduced}
	}

	// Final URL must carry the nonce.
	if nonce == "" || !strings.Contains(r.FinalURL, nonce) {
		return Result{Verdict: verdict.NotReproduced}
	}

	// Require a committed target->external transition.
	if !hasOriginTransition(r.Navigation, target, external, maxHops) &&
		!hasNetworkOriginTransition(r.Network, target, external, maxHops) {
		return Result{Verdict: verdict.NotReproduced}
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(redirectProofBlock{
			InitialOrigin: target.String(),
			FinalURL:      r.FinalURL,
			FinalOrigin:   external.String(),
			NoncePresent:  true,
		}),
		Redirects: formatNavChain(r.Navigation),
	}
}

type redirectProofBlock struct {
	InitialOrigin string `json:"initial_origin"`
	FinalURL      string `json:"final_url"`
	FinalOrigin   string `json:"final_origin"`
	NoncePresent  bool   `json:"nonce_present"`
}

// formatNavChain renders navs as "<origin> <url>".
func formatNavChain(navs []browser.NavEvent) []string {
	if len(navs) == 0 {
		return nil
	}
	out := make([]string, len(navs))
	for i, n := range navs {
		out[i] = n.Origin + " " + n.URL
	}
	return out
}

func startsAtTarget(r browser.BrowserResult, target policy.Origin) bool {
	if len(r.Navigation) > 0 {
		firstOrigin, ok := policy.ParseOrigin(r.Navigation[0].Origin)
		if ok && firstOrigin.Equal(target) {
			return true
		}
	}
	if len(r.Network) == 0 {
		return false
	}
	o, ok := originFromRawURL(r.Network[0].URL)
	return ok && o.Equal(target)
}

// hasOriginTransition checks target->external.
func hasOriginTransition(navs []browser.NavEvent, target, external policy.Origin, maxHops int) bool {
	seenTarget := false
	for i, n := range navs {
		if i >= maxHops {
			return false
		}
		o, ok := policy.ParseOrigin(n.Origin)
		if !ok {
			continue
		}
		if o.Equal(target) {
			seenTarget = true
			continue
		}
		if seenTarget && o.Equal(external) {
			return true
		}
	}
	return false
}

func hasNetworkOriginTransition(events []browser.NetEvent, target, external policy.Origin, maxHops int) bool {
	seenTarget := false
	for i, n := range events {
		if i >= maxHops {
			return false
		}
		o, ok := originFromRawURL(n.URL)
		if !ok {
			continue
		}
		if o.Equal(target) {
			seenTarget = true
			continue
		}
		if seenTarget && o.Equal(external) {
			return true
		}
	}
	return false
}

func originFromRawURL(raw string) (policy.Origin, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return policy.Origin{}, false
	}
	return policy.ParseOrigin(u.Scheme + "://" + u.Host)
}

type redirectEvidence struct {
	Entrypoint            evidence.Request `json:"entrypoint"`
	RedirectParameter     string           `json:"redirect_parameter"`
	ExpectedInitialOrigin string           `json:"expected_initial_origin"`
	ExpectedFinalOrigin   string           `json:"expected_final_origin"`
	RedirectKind          string           `json:"redirect_kind"`
	MaxHops               int              `json:"max_hops"`
}

type redirectProof struct {
	ExpectedSignal             string `json:"expected_signal"`
	RequireInitialTargetOrigin bool   `json:"require_initial_target_origin"`
	RequireFinalExternalOrigin bool   `json:"require_final_external_origin"`
	TimeoutMS                  int    `json:"timeout_ms"`
}

func init() { Register(openRedirect{}) }
