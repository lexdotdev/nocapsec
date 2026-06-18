package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/xxe-oast.md
type xxeOAST struct{}

func (xxeOAST) Type() string { return "xxe.oast" }

func (xxeOAST) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xxeOAST{}) }
