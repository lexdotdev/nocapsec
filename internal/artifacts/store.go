// Package artifacts persists the raw evidence behind every verdict with
// secrets redacted. Every artifact is addressable by a stable ref.
package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// ErrNotFound is returned when an artifact ref does not exist.
var ErrNotFound = errors.New("artifacts: not found")

// ArtifactKind categorizes a persisted artifact; values are stable refs.
type ArtifactKind string

const (
	KindEvidence       ArtifactKind = "evidence"
	KindPolicySnapshot ArtifactKind = "policy"
	KindHTTPExchange   ArtifactKind = "http_exchange"
	KindRedirectChain  ArtifactKind = "redirect_chain"
	KindBrowserEvents  ArtifactKind = "browser_events"
	KindConsoleDialog  ArtifactKind = "console_dialog"
	KindScreenshot     ArtifactKind = "screenshot"
	KindDOMSnapshot    ArtifactKind = "dom_snapshot"
	KindOASTRaw        ArtifactKind = "oast_interaction"
	KindTimingSamples  ArtifactKind = "timing_samples"
	KindVerdict        ArtifactKind = "verdict"
)

// ArtifactStore writes and reads artifacts, each addressable by a stable ref.
type ArtifactStore interface {
	Put(ctx context.Context, jobID string, kind ArtifactKind, data []byte) (ref string, err error)
	Get(ctx context.Context, ref string) ([]byte, error)
}

// memStore implements in-memory ArtifactStore with auto-sanitization.
type memStore struct {
	mu    sync.RWMutex
	blobs map[string][]byte // ref -> data
}

// NewStore returns an in-memory ArtifactStore.
func NewStore() ArtifactStore {
	return &memStore{blobs: map[string][]byte{}}
}

// Put sanitizes data, computes a content-addressed ref, and stores it.
func (s *memStore) Put(_ context.Context, jobID string, kind ArtifactKind, data []byte) (string, error) {
	clean := Sanitize(data)
	ref := buildRef(jobID, kind, clean)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[ref] = clean
	return ref, nil
}

// Get retrieves the artifact addressed by ref.
func (s *memStore) Get(_ context.Context, ref string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.blobs[ref]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

// buildRef produces a stable artifact:// ref from job, kind, and content hash.
func buildRef(jobID string, kind ArtifactKind, data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("artifact://%s/%s/%s", jobID, kind, hex.EncodeToString(h[:8]))
}
