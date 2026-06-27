package validators

import (
	"context"
	"time"
)

type commandInjectionTiming struct{}

func (commandInjectionTiming) Type() string    { return "command_injection.time_based" }
func (commandInjectionTiming) Cap() Capability { return CapTiming }

func (commandInjectionTiming) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, proof, bad := parseTimingEvidence(job.Finding)
	if bad != "" {
		return Result{Verdict: bad}, nil
	}
	return timingDifferential(ctx, env, ev, proof)
}

type commandInjectionOAST struct{}

func (commandInjectionOAST) Type() string    { return "command_injection.oast" }
func (commandInjectionOAST) Cap() Capability { return CapOAST }

func (commandInjectionOAST) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	return runOASTValidator(ctx, job, env, oastOpts{
		Purpose:            "command_injection",
		SlotKey:            "oast_host",
		RequireAttribution: true,
		DefaultWindow:      120 * time.Second,
	})
}
