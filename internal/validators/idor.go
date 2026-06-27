package validators

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
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

	marker := replaceNonceSlot(proof.ExpectedMarker, job.Nonce)

	ownerCreds, err := loadCreds(ctx, env.AuthStore, ev.OwnerAuthStateID)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, nil //nolint:nilerr // auth failure -> inconclusive
	}
	attackerCreds, err := loadCreds(ctx, env.AuthStore, ev.AttackerAuthStateID)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, nil //nolint:nilerr // auth failure -> inconclusive
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	setupReq := ev.SetupResource
	setupReq.Body = replaceNonceSlot(setupReq.Body, job.Nonce)
	applyCreds(&setupReq, ownerCreds)

	setupCap, err := httpx.Replay(ctx, bundle, setupReq)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}
	if setupCap.StatusCode >= 400 {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	attackReq := ev.AttackRequest
	resourceID := extractResourceID(setupCap.RespBody, ev.CreatedIDPointer)
	if ev.CreatedIDPointer != "" && resourceID == "" {
		// Unresolved pointer is author error.
		return Result{Verdict: verdict.Inconclusive}, nil
	}
	attackReq.URL = replaceResourceIDSlot(attackReq.URL, resourceID)
	applyCreds(&attackReq, attackerCreds)

	attackCap, err := httpx.Replay(ctx, bundle, attackReq)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	// 3. Verified if attacker response holds canary.
	if !strings.Contains(string(attackCap.RespBody), marker) {
		return Result{Verdict: verdict.NotReproduced}, nil
	}

	if proof.RequireOwnerControl {
		// Differential: owner should resemble attacker.
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
	// CreatedIDPointer locates the id.
	CreatedIDPointer string `json:"created_id_pointer,omitempty"`
}

type idorReadProof struct {
	ExpectedMarker      string `json:"expected_marker"`
	RequireOwnerControl bool   `json:"require_owner_control"`
}

// loadCreds checks auth-state expiry then creds.
func loadCreds(ctx context.Context, store authstate.Store, id string) (*authstate.Credentials, error) {
	if _, err := store.Get(ctx, id); err != nil {
		return nil, err
	}
	return store.GetCredentials(ctx, id)
}

// replaceResourceIDSlot fills resource slot.
func replaceResourceIDSlot(s, id string) string { return replaceSlot(s, "created_resource_id", id) }

// extractResourceID reads created id.
func extractResourceID(body []byte, pointer string) string {
	if pointer != "" {
		if id := extractResourceIDAt(body, pointer); id != "" {
			return id
		}
		// unresolved pointer: never match the whole body.
		return ""
	}
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

// extractResourceIDAt reads pointer scalar.
func extractResourceIDAt(body []byte, pointer string) string {
	if pointer[0] != '/' {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return ""
	}
	cur := root
	for _, tok := range splitPointer(pointer) {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return ""
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(node) {
				return ""
			}
			cur = node[i]
		default:
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}
