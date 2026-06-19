package validators

import (
	"context"
)

type sqliTiming struct{}

func (sqliTiming) Type() string    { return "sqli.time_based" }
func (sqliTiming) Cap() Capability { return CapTiming }

func (sqliTiming) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, proof, bad := parseTimingEvidence(job.Finding)
	if bad != "" {
		return Result{Verdict: bad}, nil
	}
	return timingDifferential(ctx, env, ev, proof)
}

func init() { Register(sqliTiming{}) }
