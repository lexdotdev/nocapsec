package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/path-traversal.md
type pathTraversal struct{}

func (pathTraversal) Type() string { return "path_traversal.file_read" }

func (pathTraversal) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() { Register(pathTraversal{}) }
