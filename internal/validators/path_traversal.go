package validators

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type pathTraversal struct{}

func (pathTraversal) Type() string    { return "path_traversal.file_read" }
func (pathTraversal) Cap() Capability { return CapHTTPReplay }

func (pathTraversal) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev pathTraversalEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid verdict, not an operational error
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout

	// 1. Replay candidate request.
	candidateCap, err := httpx.Replay(ctx, bundle, ev.Request)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	// 2. Replay negative control.
	controlCap, err := httpx.Replay(ctx, bundle, ev.NegativeControl)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	// 3-4. Marker must be present in candidate AND absent from control.
	candidateBody := string(candidateCap.RespBody)
	controlBody := string(controlCap.RespBody)

	for _, marker := range ev.ExpectedMarkers {
		inCandidate := strings.Contains(candidateBody, marker)
		inControl := strings.Contains(controlBody, marker)

		if inCandidate && !inControl {
			proof := proofJSON(pathTraversalProof{
				MatchedMarker:      marker,
				PresentInCandidate: true,
				AbsentInControl:    true,
				CandidateStatus:    candidateCap.StatusCode,
				ControlStatus:      controlCap.StatusCode,
			})
			return Result{
				Verdict:   verdict.Verified,
				Proof:     proof,
				Redirects: formatRedirects(candidateCap.Redirects),
			}, nil
		}
	}

	return Result{Verdict: verdict.NotReproduced}, nil
}

type pathTraversalProof struct {
	MatchedMarker      string `json:"matched_marker"`
	PresentInCandidate bool   `json:"present_in_candidate"`
	AbsentInControl    bool   `json:"absent_in_control"`
	CandidateStatus    int    `json:"candidate_status"`
	ControlStatus      int    `json:"control_status"`
}

type pathTraversalEvidence struct {
	Request         evidence.Request `json:"request"`
	VulnerableParam string           `json:"vulnerable_parameter"`
	ExpectedMarkers []string         `json:"expected_markers"`
	NegativeControl evidence.Request `json:"negative_control"`
}

func init() { Register(pathTraversal{}) }
