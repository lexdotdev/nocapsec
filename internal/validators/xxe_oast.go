package validators

import (
	"context"
	"time"
)

type xxeOAST struct{}

func (xxeOAST) Type() string    { return "xxe.oast" }
func (xxeOAST) Cap() Capability { return CapOAST }

func (xxeOAST) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	return runOASTValidator(ctx, job, env, oastOpts{
		Purpose:            "xxe",
		SlotKey:            "oast_url",
		RequireAttribution: true,
		DefaultWindow:      120 * time.Second,
	})
}
