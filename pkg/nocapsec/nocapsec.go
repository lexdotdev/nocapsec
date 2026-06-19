// Package nocapsec is the public, embeddable API for the nocapsec proof engine.
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

// ErrNotImplemented signals a Task dispatched with no Run func.
var ErrNotImplemented = engine.ErrNotImplemented

// Config holds the engine's policy defaults and concurrency limits.
type Config = engine.Config

// Engine runs the verification pipeline in-process. It is safe for concurrent
// use: Verify may be called from many goroutines against the shared worker pools.
type Engine struct {
	engine *engine.Engine
}

// New builds an Engine from cfg, wiring policy, validators, and the in-process
// worker pools. Call Close to drain them.
func New(cfg Config) (*Engine, error) {
	eng, err := engine.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Engine{engine: eng}, nil
}

// Verify runs the full pipeline for one finding and returns its terminal
// Report. finding is the finding JSON (the POST /verify body).
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
