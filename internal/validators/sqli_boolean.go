package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sqliBoolean struct{}

func (sqliBoolean) Type() string { return "sqli.boolean_based" }

func (sqliBoolean) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(sqliBoolean{}) }
