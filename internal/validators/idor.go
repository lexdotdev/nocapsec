package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type idorRead struct{}

func (idorRead) Type() string { return "idor.read" }

func (idorRead) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(idorRead{}) }
