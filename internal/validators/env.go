// Package validators runs per-type verification
// behind the policy gate.
package validators

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Clock abstracts time for deterministic timing.
type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

// PolicyEnforcer gates every URL, redirect, and
// browser proxy.
type PolicyEnforcer interface {
	CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error)
	CheckRedirect(from, to string) error
	BrowserProxyFor(job Job) (proxyURL string, cleanup func(), err error)
	// Checker exposes the policy checker to httpx.
	Checker() *policy.Checker
}

// Job is one finding plus its per-run nonce.
type Job struct {
	Finding evidence.Finding
	Nonce   string
}

// Env is per-worker infrastructure for a validator.
type Env struct {
	Browser    browser.BrowserRunner
	OAST       oast.OAST
	Policy     PolicyEnforcer
	Artifacts  artifacts.ArtifactStore
	AuthStore  authstate.Store
	Clock      Clock
	PollConfig *oast.PollConfig // nil -> validator default
}

// Capability names the worker pool needed.
type Capability string

const (
	CapHTTPReplay Capability = "http-replay"
	CapTiming     Capability = "timing"
	CapBrowser    Capability = "browser"
	CapOAST       Capability = "oast"
)

// Result is a verdict with optional proof and hops.
type Result struct {
	Verdict   verdict.Verdict
	Proof     json.RawMessage // set only when Verified
	Redirects []string        // observed redirect hops
}

// proofJSON marshals a proof block.
func proofJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b } //nolint:errchkjson // simple struct

// replaceSlot plants val at every {{token}} slot,
// raw and URL-encoded (upper/lower).
func replaceSlot(s, token, val string) string {
	s = strings.ReplaceAll(s, "{{"+token+"}}", val)
	s = strings.ReplaceAll(s, "%7B%7B"+token+"%7D%7D", val)
	return strings.ReplaceAll(s, "%7b%7b"+token+"%7d%7d", val)
}

// hasSlot reports whether s carries {{token}}.
func hasSlot(s, token string) bool {
	return strings.Contains(s, "{{"+token+"}}") ||
		strings.Contains(s, "%7B%7B"+token+"%7D%7D") ||
		strings.Contains(s, "%7b%7b"+token+"%7d%7d")
}

func replaceNonceSlot(s, nonce string) string { return replaceSlot(s, "nonce", nonce) }
func replaceMarkerSlot(s, expr string) string { return replaceSlot(s, "sqli_marker", expr) }
func hasMarkerSlot(s string) bool             { return hasSlot(s, "sqli_marker") }
func hasNonceSlot(s string) bool              { return hasSlot(s, "nonce") }

// Validator verifies a single finding type.
type Validator interface {
	Type() string
	// Cap is the capability dispatched to.
	Cap() Capability
	Validate(ctx context.Context, job Job, env Env) (Result, error)
}
