// Package engine is the in-process orchestration core: it accepts a finding,
// runs the verification pipeline, dispatches capability work to bounded
// per-capability worker pools, and tracks jobs.
package engine

import (
	"context"
	"errors"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// ErrNotImplemented is the sentinel returned by scaffold paths not yet wired.
var ErrNotImplemented = errors.New("engine: not implemented")

// Limits caps concurrent jobs per capability per target.
// A zero field takes the default; a negative field means unlimited.
type Limits struct {
	HTTPReplay int
	Timing     int
	Browser    int
	OAST       int
}

// For returns the per-target concurrency limit for capability c.
func (l Limits) For(c Capability) int {
	switch c {
	case CapHTTPReplay:
		return l.HTTPReplay
	case CapTiming:
		return l.Timing
	case CapBrowser:
		return l.Browser
	case CapOAST:
		return l.OAST
	default:
		return 0
	}
}

func DefaultLimits() Limits {
	return Limits{HTTPReplay: 5, Timing: 1, Browser: 2, OAST: 8}
}

// Config holds the engine's execution tuning. Policy defaults, the OAST backend,
// and the artifact store join it as the pipeline is wired.
//
// TODO: add Env wiring (validators.Env / PolicyEnforcer); see
// specs/contracts/library-api.md and specs/contracts/validator-env.md.
type Config struct {
	Limits Limits
}

// withDefaults fills unset (zero) limit fields so timing never falls back to
// unlimited by accident.
func (c Config) withDefaults() Config {
	d := DefaultLimits()
	if c.Limits.HTTPReplay == 0 {
		c.Limits.HTTPReplay = d.HTTPReplay
	}
	if c.Limits.Timing == 0 {
		c.Limits.Timing = d.Timing
	}
	if c.Limits.Browser == 0 {
		c.Limits.Browser = d.Browser
	}
	if c.Limits.OAST == 0 {
		c.Limits.OAST = d.OAST
	}
	return c
}

// Engine accepts findings and runs the verification pipeline on bounded
// in-process worker pools. Safe for concurrent use.
type Engine struct {
	dispatcher Dispatcher
	jobs       *jobStore
	// TODO: hold the Env, validator registry, planner, and evaluator that turn
	// a finding into dispatched Tasks; see specs/architecture/pipeline.md.
}

// New wires the dispatcher, worker pools, and job store from cfg.
//
// TODO: build the Env and PolicyEnforcer here (composition root); see
// specs/contracts/library-api.md.
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	return &Engine{
		dispatcher: newDispatcher(cfg.Limits),
		jobs:       newJobStore(),
	}, nil
}

// Verify runs the full pipeline for one finding and returns its terminal Report.
//
// TODO: drive normalizer -> policy gate -> planner -> dispatcher -> evaluator;
// see specs/architecture/pipeline.md.
func (e *Engine) Verify(ctx context.Context, finding []byte) (verdict.Report, error) {
	return verdict.Report{}, ErrNotImplemented
}

// Handler returns the HTTP API backed by this Engine.
func (e *Engine) Handler() http.Handler {
	return newServer(e).handler()
}

// Close drains and stops the worker pools.
func (e *Engine) Close() error {
	return e.dispatcher.Close()
}
