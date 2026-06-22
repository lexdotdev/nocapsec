package engine

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Logger receives structured engine events.
type Logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// SlogLogger adapts slog.
type SlogLogger struct{ L *slog.Logger }

func (s SlogLogger) Info(msg string, args ...any)  { s.L.Info(msg, args...) }
func (s SlogLogger) Error(msg string, args ...any) { s.L.Error(msg, args...) }

// Metrics tracks verdict and pool counts.
type Metrics struct {
	verdicts sync.Map
	poolJobs sync.Map
}

// NewMetrics initializes counters.
func NewMetrics() *Metrics { return &Metrics{} }

// RecordVerdict increments the counter for v.
func (m *Metrics) RecordVerdict(v verdict.Verdict) {
	c := m.verdictCounter(v)
	c.Add(1)
}

// RecordPool increments pool count.
func (m *Metrics) RecordPool(c Capability) {
	ctr := m.poolCounter(c)
	ctr.Add(1)
}

// VerdictCount returns verdict count.
func (m *Metrics) VerdictCount(v verdict.Verdict) int64 {
	c := m.verdictCounter(v)
	return c.Load()
}

// PoolCount returns pool count.
func (m *Metrics) PoolCount(c Capability) int64 {
	ctr := m.poolCounter(c)
	return ctr.Load()
}

func getOrCreateCounter(store *sync.Map, key any) *atomic.Int64 {
	val, _ := store.LoadOrStore(key, &atomic.Int64{})
	ctr, _ := val.(*atomic.Int64)
	return ctr
}

func (m *Metrics) verdictCounter(v verdict.Verdict) *atomic.Int64 {
	return getOrCreateCounter(&m.verdicts, v)
}

func (m *Metrics) poolCounter(c Capability) *atomic.Int64 {
	return getOrCreateCounter(&m.poolJobs, c)
}
