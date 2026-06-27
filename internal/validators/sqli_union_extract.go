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

type sqliUnionExtract struct{}

func (sqliUnionExtract) Type() string    { return "sqli.union_extract" }
func (sqliUnionExtract) Cap() Capability { return CapHTTPReplay }

func (sqliUnionExtract) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, ok := decodeUnionExtract(job)
	if !ok || !unionExtractValid(ev) {
		return Result{Verdict: verdict.Invalid}, nil
	}
	marker := job.Nonce
	if marker == "" {
		return Result{Verdict: verdict.Inconclusive}, nil
	}

	creds, v := loadExtractCreds(ctx, env, job.Finding.Auth)
	if v != "" {
		return Result{Verdict: v}, nil
	}

	defer runCleanup(ctx, env, job.Finding.SideEffects.Cleanup)

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	if v := plantCanary(ctx, bundle, ev, marker, creds); v != "" {
		return Result{Verdict: v}, nil
	}

	extractHas, controlHas, redirects, v := readArms(ctx, bundle, ev, marker, creds)
	if v != "" {
		return Result{Verdict: v}, nil
	}

	if !extractHas || controlHas {
		return Result{Verdict: verdict.NotReproduced}, nil
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sqliUnionExtractProofBlock{
			ExtractedMarker:       marker,
			MarkerInExtract:       true,
			MarkerAbsentInControl: true,
		}),
		Redirects: redirects,
	}, nil
}

// decodeUnionExtract unmarshals the evidence.
func decodeUnionExtract(job Job) (sqliUnionExtractEvidence, bool) {
	var ev sqliUnionExtractEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return ev, false
	}
	return ev, true
}

// unionExtractValid checks canary slot.
func unionExtractValid(ev sqliUnionExtractEvidence) bool {
	_, okC := ev.Injection.Payloads["control"]
	_, okE := ev.Injection.Payloads["extract"]
	return ev.SetupResource.Method != "" && ev.SetupResource.URL != "" &&
		ev.BaseRequest.Method != "" && ev.BaseRequest.URL != "" &&
		ev.Injection.Location.valid() && okC && okE &&
		(hasNonceSlot(ev.SetupResource.Body) || hasNonceSlot(ev.SetupResource.URL))
}

// plantCanary writes the nonce.
func plantCanary(
	ctx context.Context, bundle *httpx.ClientBundle,
	ev sqliUnionExtractEvidence, marker string, creds *authstate.Credentials,
) verdict.Verdict {
	req := ev.SetupResource
	req.Body = replaceNonceSlot(req.Body, marker)
	req.URL = replaceNonceSlot(req.URL, marker)
	applyCreds(&req, creds)

	setupCap, err := httpx.Replay(ctx, bundle, req)
	if err != nil || setupCap.StatusCode >= 400 {
		return verdict.Inconclusive
	}
	return ""
}

// readArms replays extract/control.
func readArms(
	ctx context.Context, bundle *httpx.ClientBundle,
	ev sqliUnionExtractEvidence, marker string, creds *authstate.Credentials,
) (extractHas, controlHas bool, redirects []string, v verdict.Verdict) {
	extractReq, err1 := injectValue(ev.BaseRequest, ev.Injection.Location, ev.Injection.Payloads["extract"])
	controlReq, err2 := injectValue(ev.BaseRequest, ev.Injection.Location, ev.Injection.Payloads["control"])
	if err1 != nil || err2 != nil {
		return false, false, nil, verdict.Invalid
	}
	applyCreds(&extractReq, creds)
	applyCreds(&controlReq, creds)

	extractCap, err := httpx.Replay(ctx, bundle, extractReq)
	if err != nil {
		return false, false, nil, verdict.Inconclusive
	}
	controlCap, err := httpx.Replay(ctx, bundle, controlReq)
	if err != nil {
		return false, false, nil, verdict.Inconclusive
	}
	return strings.Contains(string(extractCap.RespBody), marker),
		strings.Contains(string(controlCap.RespBody), marker),
		formatRedirects(extractCap.Redirects), ""
}

// loadExtractCreds loads auth creds when required.
func loadExtractCreds(ctx context.Context, env Env, ref evidence.AuthRef) (*authstate.Credentials, verdict.Verdict) {
	if !ref.Required {
		return nil, ""
	}
	if env.AuthStore == nil {
		return nil, verdict.Inconclusive
	}
	creds, err := loadCreds(ctx, env.AuthStore, ref.AuthStateID)
	if err != nil {
		return nil, verdict.Inconclusive
	}
	return creds, ""
}

// applyCreds appends auth headers.
func applyCreds(req *evidence.Request, creds *authstate.Credentials) {
	if creds == nil {
		return
	}
	for k, val := range creds.Headers {
		req.Headers = append(req.Headers, evidence.Header{Name: k, Value: val})
	}
}

type sqliUnionExtractEvidence struct {
	SetupResource evidence.Request  `json:"setup_resource"`
	BaseRequest   evidence.Request  `json:"base_request"`
	Injection     injectionEvidence `json:"injection"`
}

type sqliUnionExtractProofBlock struct {
	ExtractedMarker       string `json:"extracted_marker"`
	MarkerInExtract       bool   `json:"marker_in_extract"`
	MarkerAbsentInControl bool   `json:"marker_absent_in_control"`
}
