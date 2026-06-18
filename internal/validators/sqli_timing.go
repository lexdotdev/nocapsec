package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sqliTiming struct{}

func (sqliTiming) Type() string { return "sqli.time_based" }

func (sqliTiming) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(sqliTiming{}) }
