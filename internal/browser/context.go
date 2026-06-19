package browser

import (
	"context"
	"os"

	"github.com/chromedp/chromedp"
)

// ephemeralContext creates a chromedp allocator with an ephemeral user-data-dir
// that is destroyed when cleanup is called. proxyURL routes all browser egress
// through the policy CONNECT proxy.
func ephemeralContext(parent context.Context, proxyURL string) (ctx context.Context, cancel context.CancelFunc, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "nocapsec-browser-*")
	if err != nil {
		return nil, nil, nil, err
	}

	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(dir),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("no-first-run", true),
	)

	if proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(proxyURL))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, opts...)
	taskCtx, taskCancel := chromedp.NewContext(allocCtx)

	cancelAll := func() {
		taskCancel()
		allocCancel()
	}
	destroyProfile := func() {
		cancelAll()
		os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup of temp dir
	}

	return taskCtx, cancelAll, destroyProfile, nil
}
