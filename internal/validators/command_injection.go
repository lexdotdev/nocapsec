package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TODO ref specs/domains/validators/command-injection.md
type commandInjectionTiming struct{}

func (commandInjectionTiming) Type() string { return "command_injection.time_based" }

func (commandInjectionTiming) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

// TODO ref specs/domains/validators/command-injection.md
type commandInjectionOAST struct{}

func (commandInjectionOAST) Type() string { return "command_injection.oast" }

func (commandInjectionOAST) Validate(ctx context.Context, job Job, env Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() {
	Register(commandInjectionTiming{})
	Register(commandInjectionOAST{})
}
