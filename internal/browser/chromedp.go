package browser

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
)

const defaultTimeoutMS = 10000

// runner drives Chromium via CDP to execute a BrowserJob.
type runner struct {
	proxyURL string
	store    artifacts.ArtifactStore
}

// RunnerOption configures a runner.
type RunnerOption func(*runner)

// WithProxyURL routes browser egress through the policy CONNECT proxy.
func WithProxyURL(u string) RunnerOption {
	return func(r *runner) { r.proxyURL = u }
}

// WithArtifactStore enables proof-time screenshot/DOM capture.
func WithArtifactStore(s artifacts.ArtifactStore) RunnerOption {
	return func(r *runner) { r.store = s }
}

// NewRunner returns a BrowserRunner backed by chromedp.
func NewRunner(opts ...RunnerOption) BrowserRunner {
	r := &runner{}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (r *runner) Run(parent context.Context, job BrowserJob) (BrowserResult, error) {
	timeout := time.Duration(job.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeoutMS * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	taskCtx, _, cleanup, err := ephemeralContext(ctx, r.proxyURL)
	if err != nil {
		return BrowserResult{}, fmt.Errorf("browser: ephemeral context: %w", err)
	}
	defer cleanup()

	ec := &eventCollector{}
	ec.attach(taskCtx)

	entryURL := job.Entrypoint.URL
	if err := chromedp.Run(taskCtx, chromedp.Navigate(entryURL)); err != nil {
		return BrowserResult{}, fmt.Errorf("browser: navigate: %w", err)
	}

	if err := chromedp.Run(taskCtx, waitAction(job.WaitMode)); err != nil {
		return BrowserResult{}, fmt.Errorf("browser: wait: %w", err)
	}

	for _, act := range job.PostLoad {
		if err := chromedp.Run(taskCtx, runAction(act)); err != nil {
			return BrowserResult{}, fmt.Errorf("browser: post-load action %q: %w", act.Kind, err)
		}
	}

	navs, dialogs, console, netEvts := ec.snapshot()

	finalURL := entryURL
	if len(navs) > 0 {
		finalURL = navs[len(navs)-1].URL
	}

	result := BrowserResult{
		Navigation: navs,
		Dialogs:    dialogs,
		Console:    console,
		Network:    netEvts,
		FinalURL:   finalURL,
	}

	if hasProofSignal(job, dialogs, console) {
		jobID := generateJobID()
		result.ScreenshotRef, result.DOMSnapshotRef = captureArtifacts(taskCtx, r.store, jobID)
	}

	return result, nil
}

// hasProofSignal reports whether the collected events contain a signal the job
// is configured to accept.
func hasProofSignal(job BrowserJob, dialogs []DialogEvent, console []ConsoleEvent) bool {
	for _, sig := range job.AcceptSignals {
		switch sig {
		case "javascript_dialog":
			for _, d := range dialogs {
				if !d.FromVerifierHook {
					return true
				}
			}
		case "console_log":
			if len(console) > 0 {
				return true
			}
		}
	}
	return false
}

func waitAction(_ string) chromedp.Action {
	return chromedp.WaitReady("body", chromedp.ByQuery)
}

// runAction interprets a declared post-load Action.
func runAction(act Action) chromedp.Action {
	switch act.Kind {
	case "click":
		sel := act.Args["selector"]
		return chromedp.Click(sel, chromedp.ByQuery)
	case "wait_visible":
		sel := act.Args["selector"]
		return chromedp.WaitVisible(sel, chromedp.ByQuery)
	case "sleep":
		return chromedp.Sleep(500 * time.Millisecond)
	default:
		return chromedp.ActionFunc(func(context.Context) error {
			return fmt.Errorf("browser: unknown action kind %q", act.Kind)
		})
	}
}

func generateJobID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
