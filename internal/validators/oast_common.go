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

// oastEvidence is shared by the OAST validators.
type oastEvidence struct {
	Request       evidence.Request  `json:"request"`
	MutationSlots map[string]string `json:"mutation_slots"`
}

type oastProof struct {
	ExpectedSignal    string `json:"expected_signal"`
	PollWindowSeconds int    `json:"poll_window_seconds"`
}

// oastOpts varies behavior per OAST flavor.
type oastOpts struct {
	Purpose            string
	SlotKey            string
	RequireAttribution bool
	DefaultWindow      time.Duration
	ExpectedProtocols  []string
}

// allocateToken creates an OAST token.
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

// oastPollConfig builds a PollConfig w/ overrides.
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

// parseOASTJob validates OAST evidence.
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

// oastPollAndEvaluate polls, may attribute source.
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

// attributedOASTProof builds an attributed proof.
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

// runOASTValidator runs the full OAST pipeline.
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

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout
	if _, err := httpx.Replay(ctx, bundle, injected); err != nil {
		return Result{Verdict: verdict.Inconclusive}, err
	}

	return oastPollAndEvaluate(ctx, env, job, tok, proof, opts), nil
}

// injectSlot writes the OAST URL to declared slot.
func injectSlot(req evidence.Request, slotKey, slotTarget string, tok *oast.OASTToken) (evidence.Request, error) {
	oastValue := tok.URLHTTPS
	if slotKey == "oast_host" {
		oastValue = tok.Domain
	}

	// Token mode preserves surrounding payload.
	switch strings.TrimSpace(slotTarget) {
	case "{{oast_url}}":
		return substituteRequestSlot(req, "oast_url", tok.URLHTTPS), nil
	case "{{oast_host}}":
		return substituteRequestSlot(req, "oast_host", tok.Domain), nil
	}

	if slotTarget == "xml_external_entity_url" {
		if req.Body == "" {
			return evidence.Request{}, fmt.Errorf("empty body for XML entity injection")
		}
		out := req
		out.Body = replaceXMLEntityURL(req.Body, oastValue)
		return out, nil
	}

	// "body.<field>" or plain name: form body field.
	field := strings.TrimPrefix(slotTarget, "body.")
	return injectValue(req, InjectionLocation{Kind: kindForm, Name: field}, oastValue)
}

// substituteRequestSlot fills request slots.
func substituteRequestSlot(req evidence.Request, token, val string) evidence.Request {
	out := req
	out.URL = replaceSlot(out.URL, token, val)
	out.Body = replaceSlot(out.Body, token, val)
	if len(out.Headers) > 0 {
		hs := make([]evidence.Header, len(out.Headers))
		copy(hs, out.Headers)
		for i := range hs {
			hs[i].Value = replaceSlot(hs[i].Value, token, val)
		}
		out.Headers = hs
	}
	return out
}

// injectFormField sets a form field.
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

// replaceXMLEntityURL swaps first XML http(s) URL.
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
