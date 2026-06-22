package engine

import (
	"context"
	"fmt"
	"sync"

	"github.com/lexdotdev/nocapsec/internal/validators"
)

// Capability aliases validators.
type Capability = validators.Capability

const (
	CapHTTPReplay = validators.CapHTTPReplay
	CapTiming     = validators.CapTiming
	CapBrowser    = validators.CapBrowser
	CapOAST       = validators.CapOAST
)

// capabilities lists pool kinds.
var capabilities = []Capability{CapHTTPReplay, CapTiming, CapBrowser, CapOAST}

// Task is one pool job.
type Task struct {
	Capability Capability
	Target     string
	Run        func(ctx context.Context) error
}

// poolItem carries task result state.
type poolItem struct {
	ctx  context.Context
	task Task
	done chan<- error
}

// pool is one bounded worker set.
type pool struct {
	items chan poolItem
	wg    sync.WaitGroup
	stop  sync.Once
}

// newPool starts workers.
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

// submit waits for completion or cancel.
func (p *pool) submit(ctx context.Context, t Task) error {
	done := make(chan error, 1) // worker must never block
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

// close drains workers.
func (p *pool) close() {
	p.stop.Do(func() { close(p.items) })
	p.wg.Wait()
}

// runTask protects the pool.
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
