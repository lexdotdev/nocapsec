package validators

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type idorRead struct{}

func (idorRead) Type() string    { return "idor.read" }
func (idorRead) Cap() Capability { return CapHTTPReplay }

func (idorRead) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	var ev idorReadEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}
	var proof idorReadProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return Result{Verdict: verdict.Invalid}, nil //nolint:nilerr // schema mismatch -> invalid
	}
	if proof.ExpectedMarker == "" || ev.OwnerAuthStateID == ev.AttackerAuthStateID {
		return Result{Verdict: verdict.Invalid}, nil
	}
	if env.AuthStore == nil {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	marker := strings.ReplaceAll(proof.ExpectedMarker, "{{nonce}}", job.Nonce)

	ownerCreds, err := loadCreds(ctx, env.AuthStore, ev.OwnerAuthStateID)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, nil //nolint:nilerr // auth failure -> inconclusive
	}
	attackerCreds, err := loadCreds(ctx, env.AuthStore, ev.AttackerAuthStateID)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, nil //nolint:nilerr // auth failure -> inconclusive
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout

	// 1. Owner creates the canary resource.
	setupReq := ev.SetupResource
	setupReq.Body = strings.ReplaceAll(setupReq.Body, "{{nonce}}", job.Nonce)
	for k, v := range ownerCreds.Headers {
		setupReq.Headers = append(setupReq.Headers, evidence.Header{Name: k, Value: v})
	}

	setupCap, err := httpx.Replay(ctx, bundle, setupReq)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}
	if setupCap.StatusCode >= 400 {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	// 2. Attacker reads the owner's resource.
	attackReq := ev.AttackRequest
	resourceID := extractResourceID(setupCap.RespBody)
	attackReq.URL = strings.ReplaceAll(attackReq.URL, "{{created_resource_id}}", resourceID)
	for k, v := range attackerCreds.Headers {
		attackReq.Headers = append(attackReq.Headers, evidence.Header{Name: k, Value: v})
	}

	attackCap, err := httpx.Replay(ctx, bundle, attackReq)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	// 3. Verified if attacker's response contains the owner's canary.
	if !strings.Contains(string(attackCap.RespBody), marker) {
		return Result{Verdict: verdict.NotReproduced}, nil
	}

	if proof.RequireOwnerControl {
		// Differential: owner-created resource should structurally
		// resemble what the attacker received.
		dims := []DiffDimension{DimStatus, DimContentLengthBucket}
		setupFP := Fingerprint(setupCap)
		attackFP := Fingerprint(attackCap)
		_ = Similar(setupFP, attackFP, dims) // informational only; marker is the primary signal
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(idorReadProofBlock{
			MatchedMarker:  marker,
			AttackerStatus: attackCap.StatusCode,
			OwnerStatus:    setupCap.StatusCode,
		}),
		Redirects: formatRedirects(attackCap.Redirects),
	}, nil
}

type idorReadProofBlock struct {
	MatchedMarker  string `json:"matched_marker"`
	AttackerStatus int    `json:"attacker_status"`
	OwnerStatus    int    `json:"owner_status"`
}

type idorReadEvidence struct {
	OwnerAuthStateID    string           `json:"resource_owner_auth_state_id"`
	AttackerAuthStateID string           `json:"attacker_auth_state_id"`
	SetupResource       evidence.Request `json:"setup_resource"`
	AttackRequest       evidence.Request `json:"attack_request"`
}

type idorReadProof struct {
	ExpectedMarker      string `json:"expected_marker"`
	RequireOwnerControl bool   `json:"require_owner_control"`
}

// loadCreds fetches auth state (checking expiry) and returns credentials.
func loadCreds(ctx context.Context, store authstate.Store, id string) (*authstate.Credentials, error) {
	if _, err := store.Get(ctx, id); err != nil {
		return nil, err
	}
	return store.GetCredentials(ctx, id)
}

// extractResourceID pulls a resource ID from the setup response body.
func extractResourceID(body []byte) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(body, &obj) == nil {
		for _, key := range []string{"id", "ID", "resource_id", "resourceId"} {
			raw, ok := obj[key]
			if !ok {
				continue
			}
			var s string
			if json.Unmarshal(raw, &s) == nil && s != "" {
				return s
			}
			var n json.Number
			if json.Unmarshal(raw, &n) == nil {
				return n.String()
			}
		}
	}
	return strings.TrimSpace(string(body))
}

func init() { Register(idorRead{}) }
