// Package browser drives Chromium via CDP
// for client-side proof.
package browser

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// Action is one bounded post-load step.
type Action struct {
	Kind string            `json:"kind"`
	Args map[string]string `json:"args,omitempty"`
}

// NavEvent is a committed frame nav;
// origin re-checked.
type NavEvent struct {
	Origin string `json:"origin"`
	URL    string `json:"url"`
}

// DialogEvent records a JS dialog;
// hook events never count as proof.
type DialogEvent struct {
	Type             string `json:"type"`
	Message          string `json:"message"`
	SourceOrigin     string `json:"source_origin"`
	FromVerifierHook bool   `json:"from_verifier_hook"`
}

// ConsoleEvent is a captured console message.
type ConsoleEvent struct {
	Text      string `json:"text"`
	SourceURL string `json:"source_url"`
}

// NetEvent is a captured network request.
type NetEvent struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// BrowserJob is one browser proof attempt.
type BrowserJob struct {
	Entrypoint    evidence.Request `json:"entrypoint"`
	AuthStateID   string           `json:"auth_state_id,omitempty"`
	PostLoad      []Action         `json:"post_load,omitempty"`
	WaitMode      string           `json:"wait_mode"`
	TimeoutMS     int              `json:"timeout_ms"`
	AcceptSignals []string         `json:"accept_signals,omitempty"`
}

// BrowserResult is a job outcome;
// refs set only on proof.
type BrowserResult struct {
	Navigation     []NavEvent     `json:"navigation,omitempty"`
	Dialogs        []DialogEvent  `json:"dialogs,omitempty"`
	Console        []ConsoleEvent `json:"console,omitempty"`
	Network        []NetEvent     `json:"network,omitempty"`
	FinalURL       string         `json:"final_url"`
	ScreenshotRef  string         `json:"screenshot_ref,omitempty"`
	DOMSnapshotRef string         `json:"dom_snapshot_ref,omitempty"`
}

// BrowserRunner executes a BrowserJob.
type BrowserRunner interface {
	Run(ctx context.Context, job BrowserJob) (BrowserResult, error)
}
