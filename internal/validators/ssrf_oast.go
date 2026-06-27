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

	tok, v := allocateToken(ctx, env, "ssrf")
	if v != "" {
		return Result{Verdict: v}, nil
	}
	defer env.OAST.Close(ctx, tok.CorrelationID) //nolint:errcheck // best-effort cleanup

	if err := ssrfReplay(ctx, env, ev, tok); err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	return oastPollAndEvaluate(ctx, env, job, tok, oastProof{
		ExpectedSignal:    proof.ExpectedSignal,
		PollWindowSeconds: proof.PollWindowSeconds,
	}, oastOpts{
		RequireAttribution: true,
		DefaultWindow:      120 * time.Second,
		ExpectedProtocols:  ev.ExpectedProtocols,
	}), nil
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

// ssrfReplay injects the OAST URL and sends it.
func ssrfReplay(ctx context.Context, env Env, ev ssrfOASTEvidence, tok *oast.OASTToken) error {
	req, err := injectOASTURL(ev.Request, ev.InjectionLocation, tok, ev.ViaRedirect)
	if err != nil {
		return err
	}
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout
	_, err = httpx.Replay(ctx, bundle, req)
	return err
}

type ssrfOASTEvidence struct {
	Request           evidence.Request  `json:"request"`
	InjectionLocation InjectionLocation `json:"injection_location"`
	ExpectedProtocols []string          `json:"expected_protocols,omitempty"`
	// ViaRedirect: use the 302-redirector arm.
	ViaRedirect bool `json:"via_redirect,omitempty"`
}

type ssrfOASTProof struct {
	ExpectedSignal           string `json:"expected_signal"`
	PollWindowSeconds        int    `json:"poll_window_seconds"`
	RequireSourceNotVerifier bool   `json:"require_source_not_verifier"`
}

// validSSRFInjectionLocation checks slot kind.
func validSSRFInjectionLocation(loc InjectionLocation) bool {
	switch loc.Kind {
	case kindJSONBody:
		return loc.JSONPointer != ""
	case kindQuery, kindHeader:
		return loc.Name != ""
	default:
		return false
	}
}

// injectOASTURL plants callback URL.
func injectOASTURL(req evidence.Request, loc InjectionLocation, tok *oast.OASTToken, viaRedirect bool) (evidence.Request, error) {
	directURL := tok.URLHTTPS
	headerURL := tok.URLHTTP
	if viaRedirect {
		directURL = tok.URLRedirect
		headerURL = tok.URLRedirect
	}
	switch loc.Kind {
	case kindJSONBody, kindQuery:
		return injectValue(req, loc, directURL)
	case kindHeader:
		return injectValue(req, loc, stripScheme(headerURL))
	default:
		return evidence.Request{}, fmt.Errorf("unsupported injection kind %q", loc.Kind)
	}
}

// stripScheme drops a leading http(s)://.
func stripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	return strings.TrimPrefix(u, "http://")
}

// injectJSONOperator plants a JSON fragment.
func injectJSONOperator(req evidence.Request, pointer, fragment string) (evidence.Request, error) {
	var val any
	if err := json.Unmarshal([]byte(fragment), &val); err != nil {
		return evidence.Request{}, fmt.Errorf("invalid JSON fragment: %w", err)
	}
	return injectJSONValue(req, pointer, val)
}

// injectJSONValue sets value at the pointer.
func injectJSONValue(req evidence.Request, pointer string, value any) (evidence.Request, error) {
	if req.Body == "" {
		return evidence.Request{}, fmt.Errorf("empty body for JSON injection")
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

// setJSONPointer sets JSON Pointer value.
func setJSONPointer(doc []byte, pointer string, value any) ([]byte, error) {
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

// splitPointer splits a pointer, unescaping ~1/~0.
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

// setPath walks a nested map and sets the leaf.
func setPath(root any, tokens []string, value any) error {
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

// resolveTargetIPs returns IPs for attribution.
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

// verifierUA is the UA substring of the verifier.
func verifierUA() string { return "HeadlessChrome" }
