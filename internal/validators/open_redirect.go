package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/open-redirect.md
type openRedirect struct{}

func (openRedirect) Type() string { return "open_redirect" }

func (openRedirect) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(openRedirect{}) }
