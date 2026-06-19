package oast

import (
	"context"
	"time"
)

// Clock abstracts time for deterministic polling.
type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

type wallClock struct{}

func (wallClock) Now() time.Time                  { return time.Now() }
func (wallClock) Since(t time.Time) time.Duration { return time.Since(t) }

// PollConfig tunes the polling loop.
type PollConfig struct {
	Window      time.Duration // total poll window
	InitialWait time.Duration // delay before first poll
	MinInterval time.Duration // starting backoff interval
	MaxInterval time.Duration // backoff ceiling
	Multiplier  float64       // backoff growth factor
}

// PollResult is what the poller returns to the caller.
type PollResult struct {
	Interactions []Interaction
	Expired      bool // true if window closed with no match
}

// PollUntilMatch drives the polling loop for one token, returning as soon
// as at least one interaction arrives or the window expires.
func PollUntilMatch(ctx context.Context, backend OAST, tokenID string, since time.Time, cfg PollConfig, clock Clock) (*PollResult, error) {
	deadline := since.Add(cfg.Window)
	interval := cfg.MinInterval

	// Initial wait before first poll.
	if err := sleepCtx(ctx, cfg.InitialWait); err != nil {
		return nil, err
	}

	for {
		if clock.Now().After(deadline) {
			return &PollResult{Expired: true}, nil
		}

		ixns, err := backend.Poll(ctx, tokenID, since)
		if err != nil {
			return nil, err
		}
		if len(ixns) > 0 {
			return &PollResult{Interactions: ixns}, nil
		}

		if err := sleepCtx(ctx, interval); err != nil {
			return nil, err
		}
		interval = nextInterval(interval, cfg.MaxInterval, cfg.Multiplier)
	}
}

func nextInterval(current, ceiling time.Duration, multiplier float64) time.Duration {
	next := time.Duration(float64(current) * multiplier)
	if next > ceiling {
		return ceiling
	}
	return next
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
