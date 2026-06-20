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

type openRedirect struct{}

func (openRedirect) Type() string    { return "open_redirect" }
func (openRedirect) Cap() Capability { return CapBrowser }

func (openRedirect) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev redirectEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch
	}
	var pf redirectProof
	if err := json.Unmarshal(job.Finding.Proof, &pf); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch
	}

	targetOrigin, ok := policy.ParseOrigin(ev.ExpectedInitialOrigin)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	externalOrigin, ok := policy.ParseOrigin(ev.ExpectedFinalOrigin)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	if env.Browser == nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	// Inject per-run nonce so the final URL carries it.
	ev.Entrypoint.URL = replaceNonceSlot(ev.Entrypoint.URL, job.Nonce)

	if rejectScheme(ev.Entrypoint.URL) {
		return Result{Verdict: verdict.Rejected}, nil
	}

	safe, err := env.Policy.CheckURL(ev.Entrypoint.URL, policy.PhaseBrowserNav)
	if err != nil {
		return Result{Verdict: verdict.Rejected}, nil //nolint:nilerr // policy gate
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

	result, err := env.Browser.Run(ctx, browser.BrowserJob{
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

// hasOriginTransition: target->external in maxHops.
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
