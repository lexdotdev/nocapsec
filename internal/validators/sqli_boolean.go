package validators

import (
	"context"
	"encoding/json"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sqliBoolean struct{}

func (sqliBoolean) Type() string    { return "sqli.boolean_based" }
func (sqliBoolean) Cap() Capability { return CapHTTPReplay }

func (sqliBoolean) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev sqliBooleanEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}
	var proof sqliBooleanProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}

	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" || !ev.Injection.Location.valid() {
		return Result{Verdict: verdict.Invalid}, nil
	}
	arms, ok := buildBooleanArms(ev)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}

	// Engine-owned floor: status+body_hash_fuzzy;
	// clients can't weaken it.
	dims := unionDims(ParseDimensions(proof.Compare), DimStatus, DimBodyHashFuzzy)

	reps := proof.Repetitions
	if reps < 1 {
		reps = 2
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	var baselineRedirects []string
	// Repeat to check stability.
	for i := range reps {
		caps, err := replayTriple(ctx, bundle, arms)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}
		baselineRedirects = formatRedirects(caps.baseline.Redirects)

		baselineFP := Fingerprint(caps.baseline)
		trueFP := Fingerprint(caps.trueCond)
		falseFP := Fingerprint(caps.falseCond)

		trueSimilar := Similar(baselineFP, trueFP, dims)
		falseDiffers := !Similar(baselineFP, falseFP, dims)

		if !trueSimilar || !falseDiffers {
			// First-rep failure: pattern doesn't hold.
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			// Later-rep instability -> inconclusive.
			return Result{Verdict: verdict.Inconclusive}, nil
		}
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sqliBooleanProofBlock{
			Compare:                  dimStrings(dims),
			Repetitions:              reps,
			TrueSimilarToBaseline:    true,
			FalseDiffersFromBaseline: true,
		}),
		Redirects: baselineRedirects,
	}, nil
}

type sqliBooleanProofBlock struct {
	Compare                  []string `json:"compare"`
	Repetitions              int      `json:"repetitions"`
	TrueSimilarToBaseline    bool     `json:"true_similar_to_baseline"`
	FalseDiffersFromBaseline bool     `json:"false_differs_from_baseline"`
}

// booleanArms holds three arms from base_request.
type booleanArms struct {
	baseline  evidence.Request
	trueCond  evidence.Request
	falseCond evidence.Request
}

// buildBooleanArms plants payloads.
func buildBooleanArms(ev sqliBooleanEvidence) (booleanArms, bool) {
	loc := ev.Injection.Location
	baseVal, ok1 := ev.Injection.Payloads["baseline"]
	trueVal, ok2 := ev.Injection.Payloads["true_condition"]
	falseVal, ok3 := ev.Injection.Payloads["false_condition"]
	if !ok1 || !ok2 || !ok3 {
		return booleanArms{}, false
	}
	baseline, err := injectValue(ev.BaseRequest, loc, baseVal)
	if err != nil {
		return booleanArms{}, false
	}
	trueReq, err := injectValue(ev.BaseRequest, loc, trueVal)
	if err != nil {
		return booleanArms{}, false
	}
	falseReq, err := injectValue(ev.BaseRequest, loc, falseVal)
	if err != nil {
		return booleanArms{}, false
	}
	return booleanArms{baseline: baseline, trueCond: trueReq, falseCond: falseReq}, true
}

type booleanCaptures struct {
	baseline  *httpx.Capture
	trueCond  *httpx.Capture
	falseCond *httpx.Capture
}

func replayTriple(ctx context.Context, bundle *httpx.ClientBundle, arms booleanArms) (booleanCaptures, error) {
	baseline, err := httpx.Replay(ctx, bundle, arms.baseline)
	if err != nil {
		return booleanCaptures{}, err
	}
	trueCap, err := httpx.Replay(ctx, bundle, arms.trueCond)
	if err != nil {
		return booleanCaptures{}, err
	}
	falseCap, err := httpx.Replay(ctx, bundle, arms.falseCond)
	if err != nil {
		return booleanCaptures{}, err
	}
	return booleanCaptures{baseline: baseline, trueCond: trueCap, falseCond: falseCap}, nil
}

type sqliBooleanEvidence struct {
	BaseRequest evidence.Request  `json:"base_request"`
	Injection   injectionEvidence `json:"injection"`
}

type sqliBooleanProof struct {
	ExpectedTrueSimilarity bool     `json:"expected_true_similarity_to_baseline"`
	ExpectedFalseDiff      bool     `json:"expected_false_difference"`
	Compare                []string `json:"compare"`
	Repetitions            int      `json:"repetitions"`
}

func init() { Register(sqliBoolean{}) }
