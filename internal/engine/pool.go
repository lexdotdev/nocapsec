package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/lexdotdev/nocapsec/internal/validators"
)

// Capability aliases validators.Capability.
type Capability = validators.Capability

const (
	CapHTTPReplay = validators.CapHTTPReplay
	CapTiming     = validators.CapTiming
	CapBrowser    = validators.CapBrowser
	CapOAST       = validators.CapOAST
)

// capabilities lists every pool the engine starts.
var capabilities = []Capability{CapHTTPReplay, CapTiming, CapBrowser, CapOAST}

// Task is one unit of capability work for a pool.
type Task struct {
	Capability Capability
	Target     string
	Run        func(ctx context.Context) error
}

// poolItem carries a Task plus its result channel.
type poolItem struct {
	ctx  context.Context
	task Task
	done chan<- error
}

// pool is a bounded worker set fed by a channel;
// one per Capability.
type pool struct {
	items chan poolItem
	wg    sync.WaitGroup
	stop  sync.Once
}

// newPool starts worker goroutines draining queue.
func newPool(workers int) *pool {
	if workers < 1 {
		workers = 1
	}
	p := &pool{items: make(chan poolItem, workers)}
	p.wg.Add(workers)
	for range workers {
		go p.work()
	}
	return p
}

func (p *pool) work() {
	defer p.wg.Done()
	for item := range p.items {
		item.done <- runTask(item.ctx, item.task)
	}
}

// submit enqueues t, blocks until done or canceled.
func (p *pool) submit(ctx context.Context, t Task) error {
	done := make(chan error, 1) // buffered so the worker never blocks reporting
	select {
	case p.items <- poolItem{ctx: ctx, task: t, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// close stops work and drains in-flight tasks.
func (p *pool) close() {
	p.stop.Do(func() { close(p.items) })
	p.wg.Wait()
}

// runTask recovers panics so one job can't
// crash the pool.
func runTask(ctx context.Context, t Task) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine: %s task panicked: %v", t.Capability, r)
		}
	}()
	if t.Run == nil {
		return ErrNotImplemented
	}
	return t.Run(ctx)
}
