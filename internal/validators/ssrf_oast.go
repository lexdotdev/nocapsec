package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type ssrfOAST struct{}

func (ssrfOAST) Type() string    { return "ssrf.oast" }
func (ssrfOAST) Cap() Capability { return CapOAST }

func (ssrfOAST) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, proof, v := parseSSRFEvidence(job)
	if v != "" {
		return Result{Verdict: v}, nil
	}

	if _, err := env.Policy.CheckURL(ev.Request.URL, policy.PhaseInitial); err != nil {
		return Result{Verdict: verdict.Rejected}, nil
	}

	tok, v := allocateSSRFToken(ctx, env)
	if v != "" {
		return Result{Verdict: v}, nil
	}
	defer env.OAST.Close(ctx, tok.CorrelationID) //nolint:errcheck // best-effort cleanup

	if err := ssrfReplay(ctx, env, ev, tok); err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	return ssrfPollAndAttribute(ctx, env, job, ev, proof, tok), nil
}

func parseSSRFEvidence(job Job) (ssrfOASTEvidence, ssrfOASTProof, verdict.Verdict) {
	var ev ssrfOASTEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return ev, ssrfOASTProof{}, verdict.Invalid
	}
	var proof ssrfOASTProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return ev, proof, verdict.Invalid
	}
	if !validSSRFInjectionLocation(ev.InjectionLocation) {
		return ev, proof, verdict.Invalid
	}
	if ev.Request.Method == "" || ev.Request.URL == "" {
		return ev, proof, verdict.Invalid
	}
	return ev, proof, ""
}

func allocateSSRFToken(ctx context.Context, env Env) (*oast.OASTToken, verdict.Verdict) {
	if env.OAST == nil {
		return nil, verdict.Inconclusive
	}
	tok, err := env.OAST.NewInteraction(ctx, "ssrf")
	if err != nil {
		return nil, verdict.Inconclusive
	}
	return tok, ""
}

// ssrfReplay injects the OAST URL and sends the request.
func ssrfReplay(ctx context.Context, env Env, ev ssrfOASTEvidence, tok *oast.OASTToken) error {
	req, err := injectOASTURL(ev.Request, ev.InjectionLocation, tok)
	if err != nil {
		return err
	}
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout
	_, err = httpx.Replay(ctx, bundle, req)
	return err
}

func ssrfPollAndAttribute(
	ctx context.Context, env Env, job Job,
	ev ssrfOASTEvidence, proof ssrfOASTProof, tok *oast.OASTToken,
) Result {
	window := time.Duration(proof.PollWindowSeconds) * time.Second
	pollCfg := oastPollConfig(env, window, 120*time.Second)
	clock := env.Clock
	if clock == nil {
		clock = WallClock{}
	}

	result, err := oast.PollUntilMatch(ctx, env.OAST, tok.CorrelationID, tok.CreatedAt, pollCfg, clock)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}
	}
	if result.Expired {
		return Result{Verdict: verdict.NotReproduced}
	}

	protocols := ev.ExpectedProtocols
	if len(protocols) == 0 {
		protocols = tok.ExpectedProtocols
	}
	matched := oast.FilterByProtocol(result.Interactions, protocols)
	if len(matched) == 0 {
		return Result{Verdict: verdict.NotReproduced}
	}

	// Source attribution: require target infra, reject verifier browser.
	targetIPs := resolveTargetIPs(env, job)
	qualified := oast.RequireSourceNotVerifier(matched, targetIPs, verifierUA())
	if len(qualified) == 0 {
		return Result{Verdict: verdict.NotReproduced}
	}

	return Result{Verdict: verdict.Verified, Proof: proofJSON(attributedOASTProof(qualified[0]))}
}

type ssrfOASTEvidence struct {
	Request           evidence.Request      `json:"request"`
	InjectionLocation ssrfInjectionLocation `json:"injection_location"`
	ExpectedProtocols []string              `json:"expected_protocols,omitempty"`
}

type ssrfInjectionLocation struct {
	Kind        string `json:"kind"`
	JSONPointer string `json:"json_pointer"`
	Name        string `json:"name"`
}

type ssrfOASTProof struct {
	ExpectedSignal           string `json:"expected_signal"`
	PollWindowSeconds        int    `json:"poll_window_seconds"`
	RequireSourceNotVerifier bool   `json:"require_source_not_verifier"`
}

func validSSRFInjectionLocation(loc ssrfInjectionLocation) bool {
	switch loc.Kind {
	case "json_body":
		return loc.JSONPointer != ""
	case "query":
		return loc.Name != ""
	default:
		return false
	}
}

func injectOASTURL(req evidence.Request, loc ssrfInjectionLocation, tok *oast.OASTToken) (evidence.Request, error) {
	switch loc.Kind {
	case "json_body":
		return injectJSONBody(req, loc.JSONPointer, tok.URLHTTPS)
	case "query":
		return injectQuery(req, loc.Name, tok.URLHTTPS)
	default:
		return evidence.Request{}, fmt.Errorf("unsupported injection kind %q", loc.Kind)
	}
}

func injectJSONBody(req evidence.Request, pointer, value string) (evidence.Request, error) {
	if req.Body == "" {
		return evidence.Request{}, fmt.Errorf("empty body for json_body injection")
	}
	patched, err := setJSONPointer([]byte(req.Body), pointer, value)
	if err != nil {
		return evidence.Request{}, err
	}
	out := req
	out.Body = string(patched)
	return out, nil
}

func injectQuery(req evidence.Request, name, value string) (evidence.Request, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return evidence.Request{}, err
	}
	q := u.Query()
	if _, ok := q[name]; !ok {
		return evidence.Request{}, fmt.Errorf("missing query parameter %q", name)
	}
	q.Set(name, value)
	out := req
	u.RawQuery = q.Encode()
	out.URL = u.String()
	return out, nil
}

// setJSONPointer sets the value at a RFC 6901 JSON pointer.
func setJSONPointer(doc []byte, pointer string, value string) ([]byte, error) {
	if pointer == "" || pointer[0] != '/' {
		return nil, fmt.Errorf("invalid JSON pointer %q", pointer)
	}
	tokens := splitPointer(pointer)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty JSON pointer path")
	}
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("invalid JSON body: %w", err)
	}
	if err := setPath(root, tokens, value); err != nil {
		return nil, err
	}
	return json.Marshal(root)
}

// splitPointer splits "/a/b" into ["a","b"] with ~1/~0 unescaping.
func splitPointer(pointer string) []string {
	raw := pointer[1:]
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "/")
	for i, p := range parts {
		p = strings.ReplaceAll(p, "~1", "/")
		p = strings.ReplaceAll(p, "~0", "~")
		parts[i] = p
	}
	return parts
}

// setPath walks into a nested map and sets the leaf.
func setPath(root any, tokens []string, value string) error {
	current := root
	for i, tok := range tokens {
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("non-object at pointer token %q", tok)
		}
		if i == len(tokens)-1 {
			m[tok] = value
			return nil
		}
		next, exists := m[tok]
		if !exists {
			return fmt.Errorf("missing key %q in JSON body", tok)
		}
		current = next
	}
	return fmt.Errorf("empty token path")
}

// resolveTargetIPs extracts IPs from the target for attribution.
func resolveTargetIPs(env Env, job Job) []string {
	target := job.Finding.Target
	if target.ExpectedOrigin == "" {
		return nil
	}
	safe, err := env.Policy.CheckURL(target.ExpectedOrigin, policy.PhaseInitial)
	if err != nil || safe == nil {
		return nil
	}
	ips := make([]string, 0, len(safe.PinnedIP))
	for _, ip := range safe.PinnedIP {
		ips = append(ips, ip.String())
	}
	return ips
}

// verifierUA is the browser UA substring for attribution filtering.
func verifierUA() string { return "HeadlessChrome" }

func init() { Register(ssrfOAST{}) }
