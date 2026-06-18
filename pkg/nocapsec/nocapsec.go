// Package nocapsec is the public, embeddable API for the nocapsec proof engine.
//
// A Go program constructs an Engine and calls Verify with a finding (the same
// JSON accepted by POST /verify) to run the full verification pipeline
// in-process and receive a reproducible Report. The CLI and HTTP server in
// cmd/nocapsec are thin adapters over this package.
//
// This is a thin facade over internal/engine, which owns the dispatcher and
// in-process worker pools. The engine is still a scaffold and does no real work
// yet.
//
// See specs/contracts/library-api.md and specs/decisions/009-embeddable-go-api.md.
package nocapsec

import (
	"context"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/engine"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Report is the reproducible record returned for a finding.
type Report = verdict.Report

// Verdict is one of the five closed verification outcomes.
type Verdict = verdict.Verdict

// The closed verdict set, re-exported so callers never import internal packages.
const (
	Verified      = verdict.Verified
	NotReproduced = verdict.NotReproduced
	Inconclusive  = verdict.Inconclusive
	Rejected      = verdict.Rejected
	Invalid       = verdict.Invalid
)

// ErrNotImplemented is returned by the scaffold until the engine is wired.
var ErrNotImplemented = engine.ErrNotImplemented

// Config holds the engine's policy defaults, per-target concurrency limits,
// OAST backend, and artifact store.
//
// TODO: map public knobs onto engine.Config; see
// specs/architecture/execution-model.md and specs/contracts/library-api.md.
type Config struct{}

// Engine runs the verification pipeline in-process. It is safe for concurrent
// use: Verify may be called from many goroutines against the shared worker pools.
type Engine struct {
	engine *engine.Engine
}

// New builds an Engine from cfg, wiring policy, validators, and the in-process
// worker pools (internal/engine). Call Close to drain them.
func New(cfg Config) (*Engine, error) {
	eng, err := engine.New(engine.Config{})
	if err != nil {
		return nil, err
	}
	return &Engine{engine: eng}, nil
}

// Verify runs the full pipeline for one finding and returns its terminal
// Report. finding is the finding JSON (the POST /verify body).
//
// The error is non-nil only when no Report could be produced (e.g. the context
// was cancelled); every domain outcome — including Invalid and Rejected — is
// carried in Report.Verdict with a nil error.
func (e *Engine) Verify(ctx context.Context, finding []byte) (Report, error) {
	return e.engine.Verify(ctx, finding)
}

// Handler returns the HTTP API (POST /verify, GET /verify/{id},
// GET /verify/{id}/artifacts) backed by this Engine, for embedders that expose
// the service over HTTP. cmd/nocapsec serve mounts it.
func (e *Engine) Handler() http.Handler {
	return e.engine.Handler()
}

// Close drains and stops the worker pools.
func (e *Engine) Close() error {
	return e.engine.Close()
}
