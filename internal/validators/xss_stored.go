package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/xss-stored.md
type xssStored struct{}

func (xssStored) Type() string { return "xss.stored" }

func (xssStored) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xssStored{}) }
