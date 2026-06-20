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

// oastEvidence is shared across XXE, command injection, and blind XSS validators.
type oastEvidence struct {
	Request       evidence.Request  `json:"request"`
	MutationSlots map[string]string `json:"mutation_slots"`
}

type oastProof struct {
	ExpectedSignal    string `json:"expected_signal"`
	PollWindowSeconds int    `json:"poll_window_seconds"`
}

// oastOpts controls differences between OAST validator flavors.
type oastOpts struct {
	Purpose            string
	SlotKey            string
	RequireAttribution bool
	DefaultWindow      time.Duration
	ExpectedProtocols  []string
}

// allocateToken creates an OAST token for the given purpose.
func allocateToken(ctx context.Context, env Env, purpose string) (*oast.OASTToken, verdict.Verdict) {
	if env.OAST == nil {
		return nil, verdict.Inconclusive
	}
	tok, err := env.OAST.NewInteraction(ctx, purpose)
	if err != nil {
		return nil, verdict.Inconclusive
	}
	return tok, ""
}

// oastPollConfig builds a PollConfig from env overrides.
func oastPollConfig(env Env, window, defaultWindow time.Duration) oast.PollConfig {
	if window <= 0 {
		window = defaultWindow
	}
	if env.PollConfig != nil {
		cfg := *env.PollConfig
		cfg.Window = window
		return cfg
	}
	return oast.PollConfig{
		Window:      window,
		InitialWait: 2 * time.Second,
		MinInterval: 2 * time.Second,
		MaxInterval: 15 * time.Second,
		Multiplier:  1.5,
	}
}

// parseOASTJob unmarshals and validates evidence common to all OAST validators.
func parseOASTJob(job Job, slotKey string) (oastEvidence, oastProof, verdict.Verdict) {
	var ev oastEvidence
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return ev, oastProof{}, verdict.Invalid
	}
	var proof oastProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return ev, proof, verdict.Invalid
	}
	if ev.Request.Method == "" || ev.Request.URL == "" {
		return ev, proof, verdict.Invalid
	}
	if ev.MutationSlots[slotKey] == "" {
		return ev, proof, verdict.Invalid
	}
	return ev, proof, ""
}

// oastPollAndEvaluate polls for interactions and optionally applies source attribution.
func oastPollAndEvaluate(
	ctx context.Context, env Env, job Job,
	tok *oast.OASTToken, proof oastProof, opts oastOpts,
) Result {
	window := time.Duration(proof.PollWindowSeconds) * time.Second
	pollCfg := oastPollConfig(env, window, opts.DefaultWindow)
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

	protocols := opts.ExpectedProtocols
	if len(protocols) == 0 {
		protocols = tok.ExpectedProtocols
	}
	matched := oast.FilterByProtocol(result.Interactions, protocols)
	if len(matched) == 0 {
		return Result{Verdict: verdict.NotReproduced}
	}

	if opts.RequireAttribution {
		targetIPs := resolveTargetIPs(env, job)
		qualified := oast.RequireSourceNotVerifier(matched, targetIPs, verifierUA())
		if len(qualified) == 0 {
			return Result{Verdict: verdict.NotReproduced}
		}
		return Result{Verdict: verdict.Verified, Proof: proofJSON(attributedOASTProof(qualified[0]))}
	}

	return Result{Verdict: verdict.Verified, Proof: proofJSON(blindOASTProof{
		CorrelationID: matched[0].CorrelationID,
		Protocol:      matched[0].Protocol,
	})}
}

// attributedOASTProof builds the proof for OAST validators with source attribution.
func attributedOASTProof(ix oast.Interaction) oastAttributedProof {
	return oastAttributedProof{
		CorrelationID: ix.CorrelationID,
		Protocol:      ix.Protocol,
		SourceIP:      ix.SourceIP,
		AttributedTo:  "target_infra",
	}
}

type oastAttributedProof struct {
	CorrelationID string `json:"correlation_id"`
	Protocol      string `json:"protocol"`
	SourceIP      string `json:"source_ip"`
	AttributedTo  string `json:"attributed_to"`
}

type blindOASTProof struct {
	CorrelationID string `json:"correlation_id"`
	Protocol      string `json:"protocol"`
}

// runOASTValidator is the common flow for XXE, command-injection, and blind-XSS
// OAST validators: parse, policy-check, allocate token, inject, replay, poll.
func runOASTValidator(ctx context.Context, job Job, env Env, opts oastOpts) (Result, error) {
	ev, proof, bad := parseOASTJob(job, opts.SlotKey)
	if bad != "" {
		return Result{Verdict: bad}, nil
	}

	if _, err := env.Policy.CheckURL(ev.Request.URL, policy.PhaseInitial); err != nil {
		return Result{Verdict: verdict.Rejected}, nil
	}

	tok, v := allocateToken(ctx, env, opts.Purpose)
	if v != "" {
		return Result{Verdict: v}, nil
	}
	defer env.OAST.Close(ctx, tok.CorrelationID) //nolint:errcheck // best-effort

	injected, err := injectSlot(ev.Request, opts.SlotKey, ev.MutationSlots[opts.SlotKey], tok)
	if err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout
	if _, err := httpx.Replay(ctx, bundle, injected); err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	return oastPollAndEvaluate(ctx, env, job, tok, proof, opts), nil
}

// injectSlot writes the OAST URL into the declared mutation slot.
func injectSlot(req evidence.Request, slotKey, slotTarget string, tok *oast.OASTToken) (evidence.Request, error) {
	oastValue := tok.URLHTTPS
	if slotKey == "oast_host" {
		oastValue = tok.Domain
	}

	if slotTarget == "xml_external_entity_url" {
		if req.Body == "" {
			return evidence.Request{}, fmt.Errorf("empty body for XML entity injection")
		}
		out := req
		out.Body = replaceXMLEntityURL(req.Body, oastValue)
		return out, nil
	}

	// "body.<field>" or a plain field name: a form-encoded body field.
	field := strings.TrimPrefix(slotTarget, "body.")
	return injectValue(req, InjectionLocation{Kind: kindForm, Name: field}, oastValue)
}

// injectFormField replaces or inserts a field in a URL-encoded form body.
func injectFormField(body, field, value string) (string, error) {
	if body == "" {
		return url.Values{field: {value}}.Encode(), nil
	}
	vals, err := url.ParseQuery(body)
	if err != nil {
		return "", fmt.Errorf("cannot parse form body: %w", err)
	}
	vals.Set(field, value)
	return vals.Encode(), nil
}

// replaceXMLEntityURL replaces the first http(s):// URL in XML with oastURL.
func replaceXMLEntityURL(body, oastURL string) string {
	for _, prefix := range []string{"https://", "http://"} {
		idx := strings.Index(body, prefix)
		if idx < 0 {
			continue
		}
		end := idx + len(prefix)
		for end < len(body) && !isURLTerminator(body[end]) {
			end++
		}
		return body[:idx] + oastURL + body[end:]
	}
	return body
}

func isURLTerminator(c byte) bool {
	return c == '"' || c == '\'' || c == '>' || c == '<' || c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
