package validators

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type cachePoisoning struct{}

func (cachePoisoning) Type() string    { return "cache_poisoning.canary" }
func (cachePoisoning) Cap() Capability { return CapHTTPReplay }

// Validate proves private-key cache poisoning.
func (cachePoisoning) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, proof, ok := decodeCachePoison(job)
	if !ok || !ev.valid() {
		return Result{Verdict: verdict.Invalid}, nil
	}

	// Cleanup is best-effort.
	defer runCleanup(ctx, env, job.Finding.SideEffects.Cleanup)

	canary := job.Nonce
	reps := proof.Repetitions
	if reps < 1 {
		reps = 2
	}
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	var redirects []string
	for i := range reps {
		poisonKey := privateCacheKey(canary, "poison", i)
		controlKey := privateCacheKey(canary, "control", i)

		poison := substituteRequestSlot(substituteRequestSlot(ev.Poison, "cachebuster", poisonKey), "canary", canary)
		clean := substituteRequestSlot(ev.Clean, "cachebuster", poisonKey)
		control := substituteRequestSlot(ev.Control, "cachebuster", controlKey)

		poisonCap, err := httpx.Replay(ctx, bundle, poison)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}
		if poisonCap.StatusCode >= http.StatusInternalServerError {
			return Result{Verdict: verdict.Inconclusive}, nil // poison precondition unmet
		}
		cleanCap, err := httpx.Replay(ctx, bundle, clean)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}
		controlCap, err := httpx.Replay(ctx, bundle, control)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}

		cleanHas := captureContains(cleanCap, canary)
		controlHas := captureContains(controlCap, canary)
		if !cleanHas || controlHas {
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			return Result{Verdict: verdict.Inconclusive}, nil // later-rep instability
		}
		redirects = formatRedirects(cleanCap.Redirects)
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(cachePoisonProofBlock{
			Canary:              canary,
			Repetitions:         reps,
			CanaryInClean:       true,
			CanaryAbsentControl: true,
			PrivateKey:          true,
		}),
		Redirects: redirects,
	}, nil
}

// Hashing keeps the key distinct.
func privateCacheKey(nonce, role string, rep int) string {
	sum := sha256.Sum256([]byte(nonce + "|" + role + "|" + strconv.Itoa(rep)))
	return hex.EncodeToString(sum[:16])
}

// captureContains checks body and headers.
func captureContains(c *httpx.Capture, s string) bool {
	if strings.Contains(string(c.RespBody), s) {
		return true
	}
	for _, h := range c.RespHeaders {
		if strings.Contains(h.Value, s) {
			return true
		}
	}
	return false
}

func decodeCachePoison(job Job) (cachePoisonEvidence, cachePoisonProof, bool) {
	var ev cachePoisonEvidence
	if json.Unmarshal(job.Finding.Evidence, &ev) != nil {
		return ev, cachePoisonProof{}, false
	}
	var proof cachePoisonProof
	if json.Unmarshal(job.Finding.Proof, &proof) != nil {
		return ev, proof, false
	}
	return ev, proof, true
}

type cachePoisonEvidence struct {
	Poison  evidence.Request `json:"poison_request"`
	Clean   evidence.Request `json:"clean_request"`
	Control evidence.Request `json:"control_request"`
}

// valid enforces victim-shaped requests.
func (e cachePoisonEvidence) valid() bool {
	for _, r := range []evidence.Request{e.Poison, e.Clean, e.Control} {
		if r.Method == "" || r.URL == "" || !requestHasSlot(r, "cachebuster") {
			return false
		}
	}
	return requestHasSlot(e.Poison, "canary") &&
		!requestHasSlot(e.Clean, "canary") && !requestHasSlot(e.Control, "canary")
}

func requestHasSlot(req evidence.Request, token string) bool {
	if hasSlot(req.URL, token) || hasSlot(req.Body, token) {
		return true
	}
	for _, h := range req.Headers {
		if hasSlot(h.Value, token) {
			return true
		}
	}
	return false
}

type cachePoisonProof struct {
	Repetitions int `json:"repetitions"`
}

type cachePoisonProofBlock struct {
	Canary              string `json:"canary"`
	Repetitions         int    `json:"repetitions"`
	CanaryInClean       bool   `json:"canary_in_clean"`
	CanaryAbsentControl bool   `json:"canary_absent_in_control"`
	PrivateKey          bool   `json:"private_cache_key"`
}
