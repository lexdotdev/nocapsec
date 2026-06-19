package httpx

import (
	"context"
	"math/rand/v2"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// TimingSample is one measurement from a repeated timing run.
type TimingSample struct {
	Label      string
	DurationMS int64
	StatusCode int
}

// TimingRequest pairs a labeled request with a ClientBundle for measurement.
type TimingRequest struct {
	Label   string
	Request evidence.Request
	Bundle  *ClientBundle
}

// MeasureTiming runs each request in reqs the specified number of repetitions
// in randomized order. Each repetition uses a fresh connection (the timing
// client disables keep-alive and HTTP/2 mux). Results are returned in
// execution order.
func MeasureTiming(ctx context.Context, reqs []TimingRequest, repetitions int) ([]TimingSample, error) {
	if len(reqs) == 0 || repetitions < 1 {
		return nil, nil
	}

	// Build a schedule: (index into reqs) * repetitions, shuffled.
	schedule := make([]int, 0, len(reqs)*repetitions)
	for i := range reqs {
		for range repetitions {
			schedule = append(schedule, i)
		}
	}
	rand.Shuffle(len(schedule), func(i, j int) {
		schedule[i], schedule[j] = schedule[j], schedule[i]
	})

	samples := make([]TimingSample, 0, len(schedule))
	for _, idx := range schedule {
		if err := ctx.Err(); err != nil {
			return samples, err
		}
		tr := reqs[idx]
		capture, err := Replay(ctx, tr.Bundle, tr.Request)
		if err != nil {
			return samples, err
		}
		samples = append(samples, TimingSample{
			Label:      tr.Label,
			DurationMS: capture.DurationMS,
			StatusCode: capture.StatusCode,
		})
	}
	return samples, nil
}
