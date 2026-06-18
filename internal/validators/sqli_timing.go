package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/sqli-timing.md
type sqliTiming struct{}

func (sqliTiming) Type() string { return "sqli.time_based" }

func (sqliTiming) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(sqliTiming{}) }
