// Package validators orchestrates per-type verification. Each finding type has a
// validator that runs the finding against live infrastructure (HTTP client,
// headless browser, OAST) under the mandatory policy gate and returns a verdict.
//
// Validators may import the execution packages, policy, evidence, and the leaf
// packages; they sit above execution in the layering. See
// specs/domains/validators/README.md.
package validators

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// errNotImplemented is the sentinel returned by stub validators until their
// proof logic is written.
var errNotImplemented = errors.New("validator: not implemented")

// Clock abstracts time so timing-based validators and tests are deterministic.
type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

// PolicyEnforcer is the validator-facing view of the policy gate plus the
// per-job execution wiring (HTTP client and browser proxy) it hands out. Every
// URL and redirect a validator touches is checked through this interface.
type PolicyEnforcer interface {
	CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error)
	CheckRedirect(from, to string) error
	HTTPClientFor(job Job) (*http.Client, error)
	BrowserProxyFor(job Job) (proxyURL string, cleanup func(), err error)
}

// Job is a single unit of verification work: the normalized finding plus the
// per-run secrets (nonce, OAST token) the validator injects into mutation slots.
type Job struct {
	Finding   evidence.Finding
	Nonce     string
	OASTToken *oast.OASTToken
}

// Env is the ambient infrastructure a validator runs against. It is constructed
// once per worker and shared across jobs.
type Env struct {
	HTTP      *http.Client
	Browser   browser.BrowserRunner
	OAST      oast.OAST
	Policy    PolicyEnforcer
	Artifacts artifacts.ArtifactStore
	Clock     Clock
}

// Validator verifies a single finding type. Implementations are registered in
// init and looked up by Type.
type Validator interface {
	Type() string
	Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error)
}
