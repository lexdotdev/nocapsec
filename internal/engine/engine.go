// Package engine is the in-process orchestration core: it runs the verification
// pipeline, dispatches work to bounded per-capability pools, and tracks jobs.
package engine

import (
	"context"
	"errors"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// ErrNotImplemented is returned by scaffold paths not yet wired.
var ErrNotImplemented = errors.New("engine: not implemented")

// Limits caps concurrent jobs per capability per target. Zero takes the
// default; negative means unlimited.
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

// Config holds the engine's execution tuning. Policy, OAST, and artifact
// wiring join it as the pipeline is built out.
//
// TODO: add Env wiring (validators.Env / PolicyEnforcer).
type Config struct {
	Limits Limits
}

// withDefaults fills unset limits so timing never falls back to unlimited.
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

// Engine runs the verification pipeline on bounded pools. Safe for concurrent use.
type Engine struct {
	dispatcher Dispatcher
	jobs       *jobStore
	// TODO: hold the Env, validator registry, planner, and evaluator.
}

// New wires the dispatcher, worker pools, and job store from cfg.
//
// TODO: build the Env and PolicyEnforcer here (composition root).
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	return &Engine{
		dispatcher: newDispatcher(cfg.Limits),
		jobs:       newJobStore(),
	}, nil
}

// Verify runs the full pipeline for one finding and returns its terminal Report.
//
// TODO: drive normalizer -> policy gate -> planner -> dispatcher -> evaluator.
func (e *Engine) Verify(_ context.Context, _ []byte) (verdict.Report, error) {
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
