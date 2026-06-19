// Package validators runs per-type verification. Each finding type has a
// validator that exercises live infrastructure (HTTP client, browser, OAST)
// through the mandatory policy gate and returns a verdict. Validators sit above
// execution in the layering.
package validators

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Clock abstracts time so timing validators and tests are deterministic.
type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

// PolicyEnforcer is the validator-facing policy gate plus per-job execution
// wiring (HTTP client, browser proxy). Every URL and redirect goes through it.
type PolicyEnforcer interface {
	CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error)
	CheckRedirect(from, to string) error
	HTTPClientFor(job Job) (*http.Client, error)
	BrowserProxyFor(job Job) (proxyURL string, cleanup func(), err error)
	// Checker returns the underlying policy checker for httpx bundles.
	Checker() *policy.Checker
}

// Job is one unit of verification work: the normalized finding plus per-run
// secrets (nonce, OAST token) injected into mutation slots.
type Job struct {
	Finding   evidence.Finding
	Nonce     string
	OASTToken *oast.OASTToken
}

// Env is the infrastructure a validator runs against, built once per worker.
type Env struct {
	HTTP       *http.Client
	Browser    browser.BrowserRunner
	OAST       oast.OAST
	Policy     PolicyEnforcer
	Artifacts  artifacts.ArtifactStore
	AuthStore  authstate.Store
	Clock      Clock
	PollConfig *oast.PollConfig // nil -> validator default
}

// Capability names the worker pool a validator needs. Defined here (not in
// engine) so a new validator file registers its capability without editing
// engine routing — the engine maps these to its pools.
type Capability string

const (
	CapHTTPReplay Capability = "http-replay"
	CapTiming     Capability = "timing"
	CapBrowser    Capability = "browser"
	CapOAST       Capability = "oast"
)

// Result is a validator outcome: verdict plus, when verified, a type-specific
// proof block and any observed redirect hops.
type Result struct {
	Verdict   verdict.Verdict
	Proof     json.RawMessage // embedded in Report.Proof when Verified
	Redirects []string        // observed redirect hops, for the report
}

// proofJSON marshals a proof block; marshaling simple structs cannot fail.
func proofJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b } //nolint:errchkjson // simple struct

// Validator verifies a single finding type, registered in init, found by Type.
type Validator interface {
	Type() string
	// Capability the validator dispatches to.
	Cap() Capability
	Validate(ctx context.Context, job Job, env Env) (Result, error)
}
