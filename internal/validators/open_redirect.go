package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type openRedirect struct{}

func (openRedirect) Type() string { return "open_redirect" }

func (openRedirect) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(openRedirect{}) }
