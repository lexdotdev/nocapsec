package validators

import (
	"context"
	"time"
)

type xssBlind struct{}

func (xssBlind) Type() string    { return "xss.blind" }
func (xssBlind) Cap() Capability { return CapOAST }

func (xssBlind) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	return runOASTValidator(ctx, job, env, oastOpts{
		Purpose:            "blind_xss",
		SlotKey:            "oast_url",
		RequireAttribution: false,
		DefaultWindow:      900 * time.Second,
	})
}
