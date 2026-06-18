package verdict

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerdictValid(t *testing.T) {
	for _, v := range []Verdict{Verified, NotReproduced, Inconclusive, Rejected, Invalid} {
		if !v.Valid() {
			t.Errorf("%q should be valid", v)
		}
	}
	for _, v := range []Verdict{"", "maybe", "error", "VERIFIED"} {
		if v.Valid() {
			t.Errorf("%q should be invalid", v)
		}
	}
}

func TestReasonedCarriesReason(t *testing.T) {
	r := Reasoned("f1", "path_traversal.file_read", Rejected, "blocked_ip")
	if r.Verdict != Rejected || r.Reason != "blocked_ip" {
		t.Fatalf("got verdict=%q reason=%q", r.Verdict, r.Reason)
	}
	if !r.DecidedAt.IsZero() {
		t.Fatal("DecidedAt should be zero until Stamp")
	}
}

func TestProvenAttachesProofAndPolicy(t *testing.T) {
	proof, err := Proof(map[string]string{"signal": "marker", "message": "VERIFIER_CANARY"})
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	pol := PolicySummary{SchemeOK: true, InitialOriginPinned: true, FinalOriginOK: true}
	r := Proven("f2", "path_traversal.file_read", "https://app.example.com", proof, pol)

	if r.Verdict != Verified {
		t.Fatalf("verdict = %q, want verified", r.Verdict)
	}
	if r.TargetOrigin != "https://app.example.com" {
		t.Fatalf("target origin = %q", r.TargetOrigin)
	}
	if !r.Policy.SchemeOK || !r.Policy.InitialOriginPinned {
		t.Fatalf("policy not carried: %+v", r.Policy)
	}
	var got map[string]string
	if err := json.Unmarshal(r.Proof, &got); err != nil {
		t.Fatalf("proof not valid json: %v", err)
	}
	if got["signal"] != "marker" {
		t.Fatalf("proof signal = %q", got["signal"])
	}
}

func TestUnprovenIsNotReproduced(t *testing.T) {
	r := Unproven("f3", "path_traversal.file_read", "https://app.example.com", PolicySummary{SchemeOK: true})
	if r.Verdict != NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", r.Verdict)
	}
	if len(r.Proof) != 0 {
		t.Fatal("not_reproduced must carry no proof block")
	}
}

func TestStampSetsDecidedAt(t *testing.T) {
	now := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	r := Reasoned("f4", "x", Invalid, "schema_invalid").Stamp(now)
	if !r.DecidedAt.Equal(now) {
		t.Fatalf("DecidedAt = %v, want %v", r.DecidedAt, now)
	}
}

// A terminal report omits the proof, target_origin, artifacts, and reason keys
// when empty so reports stay boring and diffable.
func TestReportJSONOmitsEmpty(t *testing.T) {
	b, err := Unproven("f5", "x", "", PolicySummary{}).JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"proof", "target_origin", "artifacts", "reason"} {
		if _, ok := m[k]; ok {
			t.Errorf("empty %q should be omitted, got %s", k, b)
		}
	}
	for _, k := range []string{"finding_id", "type", "verdict", "policy", "decided_at"} {
		if _, ok := m[k]; !ok {
			t.Errorf("required key %q missing from %s", k, b)
		}
	}
}
