package engine

import (
	"context"
	"fmt"
	"sync"
)

// Dispatcher routes a Task to its pool under
// the per-target limit.
type Dispatcher interface {
	// Dispatch runs t on its pool, blocking until done.
	Dispatch(ctx context.Context, t Task) error
	// Close drains pools and stops accepting work.
	Close() error
}

// inProcessDispatcher: one pool per capability
// plus a per-key limiter.
type inProcessDispatcher struct {
	pools   map[Capability]*pool
	limiter *limiter
}

// newDispatcher starts one pool per capability.
func newDispatcher(limits Limits) *inProcessDispatcher {
	pools := make(map[Capability]*pool, len(capabilities))
	for _, c := range capabilities {
		pools[c] = newPool(limits.For(c))
	}
	return &inProcessDispatcher{pools: pools, limiter: newLimiter(limits)}
}

func (d *inProcessDispatcher) Dispatch(ctx context.Context, t Task) error {
	p, ok := d.pools[t.Capability]
	if !ok {
		return fmt.Errorf("engine: no worker pool for capability %q", t.Capability)
	}
	release, err := d.limiter.acquire(ctx, t.Capability, t.Target)
	if err != nil {
		return err
	}
	defer release()
	return p.submit(ctx, t)
}

func (d *inProcessDispatcher) Close() error {
	for _, p := range d.pools {
		p.close()
	}
	return nil
}

// limiter caps work per (capability,target);
// 0 is unlimited.
type limiter struct {
	limits Limits
	mu     sync.Mutex
	sems   map[string]chan struct{}
}

func newLimiter(limits Limits) *limiter {
	return &limiter{limits: limits, sems: map[string]chan struct{}{}}
}

// acquire blocks for a slot, returns release func.
func (l *limiter) acquire(ctx context.Context, c Capability, target string) (func(), error) {
	sem := l.semFor(c, target)
	if sem == nil {
		return func() {}, nil
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// semFor returns the key's semaphore;
// nil means unlimited.
func (l *limiter) semFor(c Capability, target string) chan struct{} {
	n := l.limits.For(c)
	if n < 1 {
		return nil
	}
	key := string(c) + "\x00" + target
	l.mu.Lock()
	defer l.mu.Unlock()
	sem, ok := l.sems[key]
	if !ok {
		sem = make(chan struct{}, n)
		l.sems[key] = sem
	}
	return sem
}
