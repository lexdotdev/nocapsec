// Package artifacts stores evidence;
// secrets redacted.
package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// ErrNotFound means the ref does not exist.
var ErrNotFound = errors.New("artifacts: not found")

// ArtifactKind categorizes a stored artifact.
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

// ArtifactStore reads/writes by stable ref.
type ArtifactStore interface {
	Put(ctx context.Context, jobID string, kind ArtifactKind, data []byte) (ref string, err error)
	Get(ctx context.Context, ref string) ([]byte, error)
}

// memStore is in-memory; sanitizes on write.
type memStore struct {
	mu    sync.RWMutex
	blobs map[string][]byte // ref -> data
}

// NewStore returns an in-memory store.
func NewStore() ArtifactStore {
	return &memStore{blobs: map[string][]byte{}}
}

// Put sanitizes data, stores it under
// a content-addressed ref.
func (s *memStore) Put(_ context.Context, jobID string, kind ArtifactKind, data []byte) (string, error) {
	clean := Sanitize(data)
	ref := buildRef(jobID, kind, clean)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[ref] = clean
	return ref, nil
}

// Get returns the artifact for ref.
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

// buildRef makes a ref: job, kind, hash.
func buildRef(jobID string, kind ArtifactKind, data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("artifact://%s/%s/%s", jobID, kind, hex.EncodeToString(h[:8]))
}
