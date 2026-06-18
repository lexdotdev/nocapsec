// Package browser drives Chromium through the Chrome DevTools Protocol (CDP) to
// prove client-side vulnerabilities. It creates an ephemeral profile per job,
// injects auth state only for the pinned origin, routes all egress through the
// policy proxy, and captures the navigation chain, dialogs, console messages,
// network events, and screenshots/DOM on proof.
//
// This package belongs to the execution layer: it may import internal/evidence
// (and the leaf packages) but is never imported by policy or evidence. See
// specs/domains/browser/README.md and
// specs/decisions/004-chromedp-cdp-browser.md.
package browser

import (
	"context"
	"errors"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// ErrNotImplemented is returned by stub runner methods until the chromedp/CDP
// session layer is built out.
var ErrNotImplemented = errors.New("browser: not implemented")

// Action is a single declared post-load step (e.g. a click or wait). Actions
// are declarative and bounded; they are not free-form scripts.
type Action struct {
	Kind string            `json:"kind"`
	Args map[string]string `json:"args,omitempty"`
}

// NavEvent is a committed frame navigation observed via CDP. The origin is
// re-checked against policy at PhaseBrowserNav.
type NavEvent struct {
	Origin string `json:"origin"`
	URL    string `json:"url"`
}

// DialogEvent records a JavaScript dialog (alert/confirm/prompt) before it is
// auto-accepted. FromVerifierHook flags dialogs emitted by our own
// instrumentation so they never count as proof.
type DialogEvent struct {
	Type             string `json:"type"`
	Message          string `json:"message"`
	SourceOrigin     string `json:"source_origin"`
	FromVerifierHook bool   `json:"from_verifier_hook"`
}

// ConsoleEvent is a captured Runtime.consoleAPICalled message.
type ConsoleEvent struct {
	Text      string `json:"text"`
	SourceURL string `json:"source_url"`
}

// NetEvent is a captured Network.requestWillBeSent event.
type NetEvent struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// BrowserJob is a single browser proof attempt.
type BrowserJob struct {
	Entrypoint    evidence.Request `json:"entrypoint"`
	AuthStateID   string           `json:"auth_state_id,omitempty"`
	PostLoad      []Action         `json:"post_load,omitempty"`
	WaitMode      string           `json:"wait_mode"`
	TimeoutMS     int              `json:"timeout_ms"`
	AcceptSignals []string         `json:"accept_signals,omitempty"`
}

// BrowserResult is the observed outcome of a BrowserJob. ScreenshotRef and
// DOMSnapshotRef are set only after a proof signal, never speculatively.
type BrowserResult struct {
	Navigation     []NavEvent     `json:"navigation,omitempty"`
	Dialogs        []DialogEvent  `json:"dialogs,omitempty"`
	Console        []ConsoleEvent `json:"console,omitempty"`
	Network        []NetEvent     `json:"network,omitempty"`
	FinalURL       string         `json:"final_url"`
	ScreenshotRef  string         `json:"screenshot_ref,omitempty"`
	DOMSnapshotRef string         `json:"dom_snapshot_ref,omitempty"`
}

// BrowserRunner executes a BrowserJob and returns the observed BrowserResult.
// It is provided to validators via the Env (see contracts/validator-env.md).
type BrowserRunner interface {
	Run(ctx context.Context, job BrowserJob) (BrowserResult, error)
}
