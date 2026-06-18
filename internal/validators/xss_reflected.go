package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xssReflected struct{}

func (xssReflected) Type() string { return "xss.reflected" }

func (xssReflected) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xssReflected{}) }
