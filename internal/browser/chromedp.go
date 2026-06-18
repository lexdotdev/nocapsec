package browser

import "context"

// stubRunner is a placeholder BrowserRunner that performs no browser work.
//
// TODO: implement CDP session lifecycle, policy-proxy egress, per-origin auth
// injection, CDP listeners, the bounded post-load interpreter, and proof-time
// screenshot/DOM capture.
type stubRunner struct{}

// Run returns a zero BrowserResult with ErrNotImplemented.
func (stubRunner) Run(context.Context, BrowserJob) (BrowserResult, error) {
	return BrowserResult{}, ErrNotImplemented
}

// NewRunner returns the default BrowserRunner.
func NewRunner() BrowserRunner {
	return stubRunner{}
}
