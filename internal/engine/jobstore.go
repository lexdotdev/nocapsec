package engine

import (
	"sync"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// jobStore holds the current Report per job,
// keyed by job ID.
type jobStore struct {
	mu   sync.RWMutex
	jobs map[string]verdict.Report
}

func newJobStore() *jobStore {
	return &jobStore{jobs: map[string]verdict.Report{}}
}

// put records the latest Report for id.
func (s *jobStore) put(id string, r verdict.Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[id] = r
}

// get returns the Report for id and if it exists.
func (s *jobStore) get(id string) (verdict.Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.jobs[id]
	return r, ok
}
