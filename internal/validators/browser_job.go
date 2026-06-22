package validators

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/browser"
)

func runBrowser(ctx context.Context, job Job, env Env, bjob browser.BrowserJob) (browser.BrowserResult, error) {
	proxyURL, cleanup, err := env.Policy.BrowserProxyFor(job)
	if err != nil {
		return browser.BrowserResult{}, err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if proxyURL != "" {
		bjob.ProxyURL = proxyURL
	}
	return env.Browser.Run(ctx, bjob)
}
