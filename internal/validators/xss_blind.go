package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/xss-blind.md
type xssBlind struct{}

func (xssBlind) Type() string { return "xss.blind" }

func (xssBlind) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xssBlind{}) }
