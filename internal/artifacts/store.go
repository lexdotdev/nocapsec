// Package artifacts persists the raw evidence behind every verdict — evidence,
// request/response pairs, redirect chains, browser events, screenshots, DOM
// snapshots, OAST interactions, and timing samples — with secrets redacted.
package artifacts

import (
	"context"
	"errors"
)

// ErrNotImplemented is the sentinel returned by stub implementations.
var ErrNotImplemented = errors.New("artifacts: not implemented")

// ArtifactKind categorizes a persisted artifact; values are stable refs.
type ArtifactKind string

// Artifact kinds. String values must remain stable once persisted.
const (
	KindEvidence       ArtifactKind = "evidence"         // normalized finding
	KindPolicySnapshot ArtifactKind = "policy"           // target policy at decision time
	KindHTTPExchange   ArtifactKind = "http_exchange"    // request/response pair
	KindRedirectChain  ArtifactKind = "redirect_chain"   // redirect hops
	KindBrowserEvents  ArtifactKind = "browser_events"   // browser navigation events
	KindConsoleDialog  ArtifactKind = "console_dialog"   // console and dialog records
	KindScreenshot     ArtifactKind = "screenshot"       // rendered screenshot
	KindDOMSnapshot    ArtifactKind = "dom_snapshot"     // serialized DOM
	KindOASTRaw        ArtifactKind = "oast_interaction" // raw OAST interaction
	KindTimingSamples  ArtifactKind = "timing_samples"   // timing measurements
	KindVerdict        ArtifactKind = "verdict"          // decided verdict report
)

// ArtifactStore writes and reads artifacts, each addressable by a stable ref
// recorded in the verdict report.
type ArtifactStore interface {
	// Put persists data for a job under kind and returns a stable ref. Callers
	// route data through Sanitize first so raw credentials never reach storage.
	Put(ctx context.Context, jobID string, kind ArtifactKind, data []byte) (ref string, err error)
	// Get retrieves the artifact addressed by ref.
	Get(ctx context.Context, ref string) ([]byte, error)
}

// memStore is a stub ArtifactStore.
//
// TODO: implement persistence (object store + Postgres metadata, immutable,
// redaction-fronted writes).
type memStore struct{}

// NewStore returns a stub ArtifactStore.
func NewStore() ArtifactStore {
	return &memStore{}
}

// Put is a stub; it returns ErrNotImplemented.
func (s *memStore) Put(context.Context, string, ArtifactKind, []byte) (string, error) {
	return "", ErrNotImplemented
}

// Get is a stub; it returns ErrNotImplemented.
func (s *memStore) Get(context.Context, string) ([]byte, error) {
	return nil, ErrNotImplemented
}
