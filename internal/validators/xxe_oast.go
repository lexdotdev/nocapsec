package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xxeOAST struct{}

func (xxeOAST) Type() string { return "xxe.oast" }

func (xxeOAST) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xxeOAST{}) }
