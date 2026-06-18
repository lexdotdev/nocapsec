package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type ssrfOAST struct{}

func (ssrfOAST) Type() string { return "ssrf.oast" }

func (ssrfOAST) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(ssrfOAST{}) }
