// Package nocapsec is the proof-engine API.
package nocapsec

import (
	"context"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/engine"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Report is the record returned for a finding.
type Report = verdict.Report

// Verdict is one of the closed verdict set.
type Verdict = verdict.Verdict

// Closed verdict set, re-exported for callers.
const (
	Verified      = verdict.Verified
	NotReproduced = verdict.NotReproduced
	Inconclusive  = verdict.Inconclusive
	Rejected      = verdict.Rejected
	Invalid       = verdict.Invalid
)

// Config holds defaults + concurrency limits.
type Config = engine.Config

// Engine runs the pipeline; concurrency-safe.
type Engine struct {
	engine *engine.Engine
}

// New builds an Engine; call Close to drain pools.
func New(cfg Config) (*Engine, error) {
	eng, err := engine.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Engine{engine: eng}, nil
}

// Verify runs the pipeline for one finding (JSON).
func (e *Engine) Verify(ctx context.Context, finding []byte) (Report, error) {
	return e.engine.Verify(ctx, finding)
}

// Handler returns the HTTP API for this Engine.
func (e *Engine) Handler() http.Handler {
	return e.engine.Handler()
}

// Close drains and stops the pools.
func (e *Engine) Close() error {
	return e.engine.Close()
}
