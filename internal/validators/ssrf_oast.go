package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/ssrf-oast.md
type ssrfOAST struct{}

func (ssrfOAST) Type() string { return "ssrf.oast" }

func (ssrfOAST) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(ssrfOAST{}) }
