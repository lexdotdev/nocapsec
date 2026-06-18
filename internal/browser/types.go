// Package browser drives Chromium over the Chrome DevTools Protocol to prove
// client-side vulnerabilities. Per job it uses an ephemeral profile, injects
// auth only for the pinned origin, routes egress through the policy proxy, and
// captures navigation, dialogs, console, network, and screenshots/DOM on proof.
package browser

import (
	"context"
	"errors"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// ErrNotImplemented is returned by stub runner methods.
var ErrNotImplemented = errors.New("browser: not implemented")

// Action is one declared post-load step (click, wait). Bounded, not a script.
type Action struct {
	Kind string            `json:"kind"`
	Args map[string]string `json:"args,omitempty"`
}

// NavEvent is a committed frame navigation; its origin is re-checked at
// PhaseBrowserNav.
type NavEvent struct {
	Origin string `json:"origin"`
	URL    string `json:"url"`
}

// DialogEvent records a JS dialog before auto-accept. FromVerifierHook marks
// our own instrumentation so it never counts as proof.
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

// BrowserResult is a BrowserJob's outcome. ScreenshotRef and DOMSnapshotRef are
// set only after a proof signal, never speculatively.
type BrowserResult struct {
	Navigation     []NavEvent     `json:"navigation,omitempty"`
	Dialogs        []DialogEvent  `json:"dialogs,omitempty"`
	Console        []ConsoleEvent `json:"console,omitempty"`
	Network        []NetEvent     `json:"network,omitempty"`
	FinalURL       string         `json:"final_url"`
	ScreenshotRef  string         `json:"screenshot_ref,omitempty"`
	DOMSnapshotRef string         `json:"dom_snapshot_ref,omitempty"`
}

// BrowserRunner executes a BrowserJob, provided to validators via the Env.
type BrowserRunner interface {
	Run(ctx context.Context, job BrowserJob) (BrowserResult, error)
}
