// Package artifacts persists the raw evidence behind every verdict —
// normalized evidence, request/response pairs, redirect chains, browser
// events, console/dialog records, screenshots, DOM snapshots, OAST
// interactions, and timing samples — with secrets redacted.
//
// See specs/domains/artifacts/README.md for the domain contract.
package artifacts

import (
	"context"
	"errors"
)

// ErrNotImplemented is the sentinel returned by stub implementations.
var ErrNotImplemented = errors.New("artifacts: not implemented")

// ArtifactKind identifies the category of a persisted artifact. String values
// are stable identifiers recorded alongside each artifact ref.
type ArtifactKind string

// Artifact kinds. String values are defined by
// specs/domains/artifacts/README.md and must remain stable once persisted.
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

// ArtifactStore writes and reads artifacts. Metadata lives in Postgres and
// blobs live in object storage; every artifact is addressable by a stable ref
// recorded in the verdict report.
type ArtifactStore interface {
	// Put persists data for the given job under the given kind and returns a
	// stable ref (artifact://...). Callers must route data through Sanitize
	// before persistence so raw credentials never reach storage.
	Put(ctx context.Context, jobID string, kind ArtifactKind, data []byte) (ref string, err error)
	// Get retrieves the artifact addressed by ref.
	Get(ctx context.Context, ref string) ([]byte, error)
}

// memStore is a stub ArtifactStore. A future implementation will store
// metadata in Postgres and blobs in object storage.
//
// TODO: implement persistence per specs/domains/artifacts/README.md
// (object store + Postgres metadata, immutable, redaction-fronted writes).
type memStore struct{}

// NewStore returns a stub ArtifactStore.
func NewStore() ArtifactStore {
	return &memStore{}
}

// Put is a stub; it returns ErrNotImplemented.
func (s *memStore) Put(ctx context.Context, jobID string, kind ArtifactKind, data []byte) (string, error) {
	return "", ErrNotImplemented
}

// Get is a stub; it returns ErrNotImplemented.
func (s *memStore) Get(ctx context.Context, ref string) ([]byte, error) {
	return nil, ErrNotImplemented
}
