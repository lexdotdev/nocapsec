// Package validators runs per-type verification. Each finding type has a
// validator that exercises live infrastructure (HTTP client, browser, OAST)
// through the mandatory policy gate and returns a verdict. Validators sit above
// execution in the layering.
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

// errNotImplemented is returned by stub validators.
var errNotImplemented = errors.New("validator: not implemented")

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
	HTTP      *http.Client
	Browser   browser.BrowserRunner
	OAST      oast.OAST
	Policy    PolicyEnforcer
	Artifacts artifacts.ArtifactStore
	Clock     Clock
}

// Validator verifies a single finding type, registered in init, found by Type.
type Validator interface {
	Type() string
	Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error)
}
