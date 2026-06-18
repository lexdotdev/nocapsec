package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type xssStored struct{}

func (xssStored) Type() string { return "xss.stored" }

func (xssStored) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(xssStored{}) }
