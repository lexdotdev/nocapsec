package validators

import (
	"context"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// computedMarkerResult: marker proof outcome.
type computedMarkerResult struct {
	verdict   verdict.Verdict
	product   string
	reps      int
	redirects []string
}

// verifyComputedMarker: A*B eval-channel proof.
func verifyComputedMarker(
	ctx context.Context, env Env,
	base evidence.Request, loc InjectionLocation,
	control, candidate, markerToken string, reps int,
) (computedMarkerResult, error) {
	if reps < 1 {
		reps = 2
	}
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	var lastProduct string
	var lastRedirects []string
	for i := range reps {
		expr, product := newComputedMarker()
		cand, err1 := injectValue(base, loc, replaceSlot(candidate, markerToken, expr))
		ctl, err2 := injectValue(base, loc, replaceSlot(control, markerToken, expr))
		if err1 != nil || err2 != nil {
			return computedMarkerResult{verdict: verdict.Invalid}, nil //nolint:nilerr // bad injection slot -> invalid
		}
		candHas, ctlHas, redirects, err := replayMarkerPair(ctx, bundle, cand, ctl, product)
		if err != nil {
			return computedMarkerResult{verdict: verdict.Inconclusive}, err
		}
		// candidate computes product; control must not.
		if !candHas || ctlHas {
			if i == 0 {
				return computedMarkerResult{verdict: verdict.NotReproduced}, nil
			}
			return computedMarkerResult{verdict: verdict.Inconclusive}, nil // later-rep instability
		}
		lastProduct, lastRedirects = product, redirects
	}

	return computedMarkerResult{
		verdict:   verdict.Verified,
		product:   lastProduct,
		reps:      reps,
		redirects: lastRedirects,
	}, nil
}

// replayMarkerPair sends arms, checks product.
func replayMarkerPair(
	ctx context.Context, bundle *httpx.ClientBundle, cand, ctl evidence.Request, product string,
) (candHas, ctlHas bool, redirects []string, err error) {
	candCap, err := httpx.Replay(ctx, bundle, cand)
	if err != nil {
		return false, false, nil, err
	}
	ctlCap, err := httpx.Replay(ctx, bundle, ctl)
	if err != nil {
		return false, false, nil, err
	}
	candHas = strings.Contains(string(candCap.RespBody), product)
	ctlHas = strings.Contains(string(ctlCap.RespBody), product)
	return candHas, ctlHas, formatRedirects(candCap.Redirects), nil
}

// stableContrast replays fixed arms reps times.
// "" verdict = marker in candidate-only every rep.
func stableContrast(
	ctx context.Context, bundle *httpx.ClientBundle,
	cand, ctl evidence.Request, marker string, reps int,
) (redirects []string, v verdict.Verdict, err error) {
	for i := range reps {
		candHas, ctlHas, hops, rerr := replayMarkerPair(ctx, bundle, cand, ctl, marker)
		if rerr != nil {
			return nil, verdict.Inconclusive, rerr
		}
		if !candHas || ctlHas {
			if i == 0 {
				return nil, verdict.NotReproduced, nil
			}
			return nil, verdict.Inconclusive, nil // later-rep instability
		}
		redirects = hops
	}
	return redirects, "", nil
}

// newComputedMarker: "A*B" expr and product.
func newComputedMarker() (expr, product string) {
	a, b := randOperand(), randOperand()
	expr = strconv.FormatInt(a, 10) + "*" + strconv.FormatInt(b, 10)
	product = strconv.FormatInt(a*b, 10)
	return expr, product
}

// randOperand: a 5-digit operand (int64-safe).
func randOperand() int64 { return 10000 + int64(rand.IntN(90000)) } //nolint:gosec // anti-reflection
