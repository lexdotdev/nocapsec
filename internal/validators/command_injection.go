package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type commandInjectionTiming struct{}

func (commandInjectionTiming) Type() string { return "command_injection.time_based" }

func (commandInjectionTiming) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

type commandInjectionOAST struct{}

func (commandInjectionOAST) Type() string { return "command_injection.oast" }

func (commandInjectionOAST) Validate(context.Context, Job, Env) (verdict.Verdict, error) {
	return verdict.Inconclusive, errNotImplemented
}

func init() {
	Register(commandInjectionTiming{})
	Register(commandInjectionOAST{})
}
