package browser

import "context"

// stubRunner is a placeholder BrowserRunner that performs no browser work.
//
// TODO: implement chromedp/CDP session setup and teardown, policy-proxy egress,
// per-origin auth-state injection, CDP listeners (dialog/console/navigation/
// network), the bounded post-load action interpreter, and proof-time screenshot
// and DOM capture. See specs/domains/browser/README.md and
// specs/decisions/004-chromedp-cdp-browser.md.
type stubRunner struct{}

// Run is unimplemented and returns a zero BrowserResult with ErrNotImplemented.
func (stubRunner) Run(ctx context.Context, job BrowserJob) (BrowserResult, error) {
	return BrowserResult{}, ErrNotImplemented
}

// NewRunner returns the default BrowserRunner.
func NewRunner() BrowserRunner {
	return stubRunner{}
}
