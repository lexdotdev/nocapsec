package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xssBlind struct{}

func (xssBlind) Type() string { return "xss.blind" }

func (xssBlind) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xssBlind{}) }
