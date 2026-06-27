package validators

import (
	"net/url"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xssProofBlock struct {
	Signal               string `json:"signal"`
	ExecutionOrigin      string `json:"execution_origin"`
	MessageContainsNonce bool   `json:"message_contains_nonce"`
}

type xssProof struct {
	AcceptedSignals         []string `json:"accepted_signals"`
	ExpectedMessageContains string   `json:"expected_message_contains"`
	ExpectedExecutionOrigin string   `json:"expected_execution_origin"`
	AllowIframeExecution    bool     `json:"allow_iframe_execution"`
	TimeoutMS               int      `json:"timeout_ms"`
}

func xssVerdict(result browser.BrowserResult, pf xssProof, target policy.Origin, nonce string) Result {
	if navigatedExternal(result.Navigation, target) {
		return Result{Verdict: verdict.NotReproduced}
	}
	if signal, ok := qualifyingSignal(result, pf, target, nonce); ok {
		return Result{Verdict: verdict.Verified, Proof: proofJSON(xssProofBlock{
			Signal:               signal,
			ExecutionOrigin:      target.String(),
			MessageContainsNonce: true,
		})}
	}
	return Result{Verdict: verdict.NotReproduced}
}

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
