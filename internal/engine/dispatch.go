package engine

import (
	"context"
	"fmt"
	"sync"
)

// Dispatcher routes a Task to the worker pool for its Capability under the
// per-target concurrency limit.
type Dispatcher interface {
	// Dispatch runs t on its capability's pool and blocks until it completes.
	Dispatch(ctx context.Context, t Task) error
	// Close drains the pools and stops accepting work.
	Close() error
}

// inProcessDispatcher is the default Dispatcher: one bounded pool per capability
// plus a per-(capability,target) semaphore limiter.
type inProcessDispatcher struct {
	pools   map[Capability]*pool
	limiter *limiter
}

// newDispatcher starts one pool per capability sized by limits.
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

// limiter caps concurrent work per (capability, target) with one semaphore per
// key, sized to the capability's limit. A non-positive limit means unlimited.
type limiter struct {
	limits Limits
	mu     sync.Mutex
	sems   map[string]chan struct{}
}

func newLimiter(limits Limits) *limiter {
	return &limiter{limits: limits, sems: map[string]chan struct{}{}}
}

// acquire blocks for a slot on (capability,target) and returns a release func.
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

// semFor returns the semaphore for the key, creating it on first use; nil means
// the capability is unlimited.
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
