package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// timingEvidence is shared by sqli.time_based and command_injection.time_based.
// The engine builds control/low/high from one base_request by planting each
// payload value into the declared injection slot.
type timingEvidence struct {
	BaseRequest evidence.Request  `json:"base_request"`
	Injection   injectionEvidence `json:"injection"`
}

// timingProof configures the timing differential measurement.
type timingProof struct {
	Repetitions        int   `json:"repetitions"`
	MinMedianDeltaMS   int64 `json:"min_median_delta_ms"`
	RequireBodySimilar bool  `json:"require_body_similarity"`
	TimeoutMS          int64 `json:"timeout_ms"`
}

func (p timingProof) reps() int {
	if p.Repetitions < 3 {
		return 3
	}
	return p.Repetitions
}

func (p timingProof) minDelta() int64 {
	if p.MinMedianDeltaMS <= 0 {
		return 3000
	}
	return p.MinMedianDeltaMS
}

// timingSample records one measurement from a timed replay.
type timingSample struct {
	label      string
	durationMS int64
	statusCode int
	body       []byte
}

const (
	labelControl   = "control"
	labelDelayLow  = "delay_low"
	labelDelayHigh = "delay_high"
)

// timingDifferential runs the full timing proof: randomized measurement, median
// analysis, control stability, body/status similarity. Shared between
// sqli.time_based and command_injection.time_based.
func timingDifferential(ctx context.Context, env Env, ev timingEvidence, proof timingProof) (Result, error) {
	bundle := httpx.NewTimingClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout

	reps := proof.reps()
	samples, err := measureTimingWithClock(ctx, env.Clock, bundle, ev, reps)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	return analyzeTimingSamples(samples, proof), nil
}

// labeledReq is one timing arm: a label and the request the engine built for it.
type labeledReq struct {
	label string
	req   evidence.Request
}

// buildTimingArms plants each payload value into the declared slot of
// base_request, producing the control/low/high arms. A missing payload key or
// an inject error (slot absent from base_request) is an error.
func buildTimingArms(ev timingEvidence) ([]labeledReq, error) {
	loc := ev.Injection.Location
	out := make([]labeledReq, 0, 3)
	for _, label := range []string{labelControl, labelDelayLow, labelDelayHigh} {
		val, ok := ev.Injection.Payloads[label]
		if !ok {
			return nil, fmt.Errorf("missing payload %q", label)
		}
		req, err := injectValue(ev.BaseRequest, loc, val)
		if err != nil {
			return nil, err
		}
		out = append(out, labeledReq{label, req})
	}
	return out, nil
}

// measureTimingWithClock runs control/low/high requests in randomized order,
// timing each via the injected Clock for deterministic tests.
func measureTimingWithClock(ctx context.Context, clock Clock, bundle *httpx.ClientBundle, ev timingEvidence, reps int) ([]timingSample, error) {
	// Build the three labeled arms once, before the schedule loop.
	reqs, err := buildTimingArms(ev)
	if err != nil {
		return nil, err
	}

	// Build schedule: each request repeated reps times, then shuffled.
	schedule := make([]int, 0, len(reqs)*reps)
	for i := range reqs {
		for range reps {
			schedule = append(schedule, i)
		}
	}
	rand.Shuffle(len(schedule), func(i, j int) {
		schedule[i], schedule[j] = schedule[j], schedule[i]
	})

	samples := make([]timingSample, 0, len(schedule))
	for _, idx := range schedule {
		if err := ctx.Err(); err != nil {
			return samples, err
		}
		lr := reqs[idx]

		start := clock.Now()
		capture, err := httpx.Replay(ctx, bundle, lr.req)
		elapsed := clock.Since(start)
		if err != nil {
			return samples, err
		}

		samples = append(samples, timingSample{
			label:      lr.label,
			durationMS: elapsed.Milliseconds(),
			statusCode: capture.StatusCode,
			body:       capture.RespBody,
		})
	}
	return samples, nil
}

// analyzeTimingSamples applies the timing proof rule to collected samples.
func analyzeTimingSamples(samples []timingSample, proof timingProof) Result {
	byLabel := map[string][]timingSample{}
	for _, s := range samples {
		byLabel[s.label] = append(byLabel[s.label], s)
	}

	controlSamples := byLabel[labelControl]
	lowSamples := byLabel[labelDelayLow]
	highSamples := byLabel[labelDelayHigh]

	if len(controlSamples) == 0 || len(lowSamples) == 0 || len(highSamples) == 0 {
		return Result{Verdict: verdict.Inconclusive}
	}

	// Check control stability: if variance is too high, inconclusive.
	if !controlStable(controlSamples) {
		return Result{Verdict: verdict.Inconclusive}
	}

	// Check status code comparability across variants.
	if !statusCodesComparable(controlSamples, lowSamples, highSamples) {
		return Result{Verdict: verdict.Inconclusive}
	}

	// Check body similarity if required.
	if proof.RequireBodySimilar && !bodiesSimilar(lowSamples, highSamples) {
		return Result{Verdict: verdict.Inconclusive}
	}

	medianLow := medianDuration(lowSamples)
	medianHigh := medianDuration(highSamples)
	delta := medianHigh - medianLow
	threshold := proof.minDelta()

	if delta >= threshold {
		return Result{
			Verdict: verdict.Verified,
			Proof: proofJSON(timingProofBlock{
				MedianLowMS:  medianLow,
				MedianHighMS: medianHigh,
				DeltaMS:      delta,
				ThresholdMS:  threshold,
				Repetitions:  proof.reps(),
			}),
		}
	}
	return Result{Verdict: verdict.NotReproduced}
}

type timingProofBlock struct {
	MedianLowMS  int64 `json:"median_low_ms"`
	MedianHighMS int64 `json:"median_high_ms"`
	DeltaMS      int64 `json:"delta_ms"`
	ThresholdMS  int64 `json:"threshold_ms"`
	Repetitions  int   `json:"repetitions"`
}

// controlStable checks that control latency variance is within bounds.
// A coefficient of variation above 0.5 signals an unstable target.
func controlStable(samples []timingSample) bool {
	if len(samples) < 2 {
		return true
	}
	durations := make([]int64, len(samples))
	var sum int64
	for i, s := range samples {
		durations[i] = s.durationMS
		sum += s.durationMS
	}
	mean := sum / int64(len(durations))
	if mean == 0 {
		return true
	}
	var varianceSum int64
	for _, d := range durations {
		diff := d - mean
		varianceSum += diff * diff
	}
	variance := varianceSum / int64(len(durations))

	// CV > 0.5 is unstable. Compare variance > (0.25 * mean^2).
	return variance*4 <= mean*mean
}

// statusCodesComparable checks that all variants returned the same mode status.
func statusCodesComparable(control, low, high []timingSample) bool {
	cMode := modeStatus(control)
	lMode := modeStatus(low)
	hMode := modeStatus(high)
	return cMode == lMode && cMode == hMode
}

func modeStatus(samples []timingSample) int {
	counts := map[int]int{}
	for _, s := range samples {
		counts[s.statusCode]++
	}
	best, bestN := 0, 0
	for code, n := range counts {
		if n > bestN || (n == bestN && code < best) {
			best, bestN = code, n
		}
	}
	return best
}

// bodiesSimilar checks that low and high responses have similar structure
// using the diff fingerprint on the first sample of each.
func bodiesSimilar(low, high []timingSample) bool {
	if len(low) == 0 || len(high) == 0 {
		return false
	}
	fpLow := Fingerprint(&httpx.Capture{StatusCode: low[0].statusCode, RespBody: low[0].body})
	fpHigh := Fingerprint(&httpx.Capture{StatusCode: high[0].statusCode, RespBody: high[0].body})
	dims := []DiffDimension{DimContentLengthBucket, DimSemanticMarkers}
	return Similar(fpLow, fpHigh, dims)
}

func medianDuration(samples []timingSample) int64 {
	ds := make([]int64, len(samples))
	for i, s := range samples {
		ds[i] = s.durationMS
	}
	slices.Sort(ds)
	return ds[len(ds)/2]
}

// parseTimingEvidence unmarshals and validates the timing evidence and proof.
// A bad base_request, an invalid injection location, a missing payload key, or
// an inject error (slot absent from base_request) all yield invalid.
func parseTimingEvidence(finding evidence.Finding) (timingEvidence, timingProof, verdict.Verdict) {
	var ev timingEvidence
	if err := json.Unmarshal(finding.Evidence, &ev); err != nil {
		return ev, timingProof{}, verdict.Invalid
	}
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" || !ev.Injection.Location.valid() {
		return ev, timingProof{}, verdict.Invalid
	}
	if _, err := buildTimingArms(ev); err != nil {
		return ev, timingProof{}, verdict.Invalid
	}

	var proof timingProof
	if finding.Proof != nil {
		if err := json.Unmarshal(finding.Proof, &proof); err != nil {
			return ev, proof, verdict.Invalid
		}
	}
	return ev, proof, ""
}
