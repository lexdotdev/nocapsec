package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/xss-reflected.md
type xssReflected struct{}

func (xssReflected) Type() string { return "xss.reflected" }

func (xssReflected) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xssReflected{}) }
