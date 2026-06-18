package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type pathTraversal struct{}

func (pathTraversal) Type() string { return "path_traversal.file_read" }

func (pathTraversal) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(pathTraversal{}) }
