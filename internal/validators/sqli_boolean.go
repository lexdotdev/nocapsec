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

	dims := ParseDimensions(proof.Compare)
	if len(dims) == 0 {
		return Result{Verdict: verdict.Invalid}, nil
	}
	reps := proof.Repetitions
	if reps < 1 {
		reps = 2
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout

	var baselineRedirects []string
	// Run multiple repetitions to check stability.
	for i := range reps {
		caps, err := replayTriple(ctx, bundle, ev)
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
			// If this is the first rep and we already fail, the
			// pattern simply doesn't hold.
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			// Stability broken on a later rep -> inconclusive.
			return Result{Verdict: verdict.Inconclusive}, nil
		}
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sqliBooleanProofBlock{
			Compare:                  proof.Compare,
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

type booleanCaptures struct {
	baseline  *httpx.Capture
	trueCond  *httpx.Capture
	falseCond *httpx.Capture
}

func replayTriple(ctx context.Context, bundle *httpx.ClientBundle, ev sqliBooleanEvidence) (booleanCaptures, error) {
	baseline, err := httpx.Replay(ctx, bundle, ev.Requests.Baseline)
	if err != nil {
		return booleanCaptures{}, err
	}
	trueCap, err := httpx.Replay(ctx, bundle, ev.Requests.TrueCondition)
	if err != nil {
		return booleanCaptures{}, err
	}
	falseCap, err := httpx.Replay(ctx, bundle, ev.Requests.FalseCondition)
	if err != nil {
		return booleanCaptures{}, err
	}
	return booleanCaptures{baseline: baseline, trueCond: trueCap, falseCond: falseCap}, nil
}

type sqliBooleanEvidence struct {
	Requests struct {
		Baseline       evidence.Request `json:"baseline"`
		TrueCondition  evidence.Request `json:"true_condition"`
		FalseCondition evidence.Request `json:"false_condition"`
	} `json:"requests"`
	VulnerableParam string `json:"vulnerable_parameter"`
}

type sqliBooleanProof struct {
	ExpectedTrueSimilarity bool     `json:"expected_true_similarity_to_baseline"`
	ExpectedFalseDiff      bool     `json:"expected_false_difference"`
	Compare                []string `json:"compare"`
	Repetitions            int      `json:"repetitions"`
}

func init() { Register(sqliBoolean{}) }
