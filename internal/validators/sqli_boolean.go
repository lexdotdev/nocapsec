package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/sqli-boolean.md
type sqliBoolean struct{}

func (sqliBoolean) Type() string { return "sqli.boolean_based" }

func (sqliBoolean) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(sqliBoolean{}) }
