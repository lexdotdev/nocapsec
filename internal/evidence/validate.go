package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Stable reason codes for an invalid finding, surfaced in a report's reason.
const (
	ReasonEmptyBody         = "empty_body"
	ReasonMalformedJSON     = "malformed_json"
	ReasonUnknownField      = "unknown_field"
	ReasonMissingField      = "missing_field"
	ReasonWrongType         = "wrong_type"
	ReasonProseOnly         = "prose_only"
	ReasonUnknownType       = "unknown_type"
	ReasonInlinedCredential = "inlined_credential" //nolint:gosec // G101 false positive: a reason code, not a secret
	ReasonBadRequest        = "bad_request"
	ReasonBadURL            = "bad_url"
	ReasonDanglingSlot      = "dangling_mutation_slot"
)

// InvalidError says why a finding is invalid; it unwraps to ErrInvalid and
// Reason is the stable report code.
type InvalidError struct {
	Reason string
	Field  string
	cause  error
}

func (e *InvalidError) Error() string {
	msg := "evidence: " + e.Reason
	if e.Field != "" {
		msg += " (" + e.Field + ")"
	}
	if e.cause != nil {
		msg += ": " + e.cause.Error()
	}
	return msg
}

func (e *InvalidError) Unwrap() error { return ErrInvalid }

func invalid(reason, field string, cause error) *InvalidError {
	return &InvalidError{Reason: reason, Field: field, cause: cause}
}

// Parse turns untrusted client JSON into a canonical, validated Finding:
// validate envelope, reject prose-only/unknown types, check the per-type
// shape, canonicalize, and verify every slot resolves. Failure yields a
// wrapped ErrInvalid with a stable reason and no execution.
func Parse(raw []byte) (*Finding, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, invalid(ReasonEmptyBody, "", nil)
	}
	if err := validateEnvelope(raw); err != nil {
		return nil, err
	}

	var f Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, invalid(ReasonWrongType, "", err)
	}

	ts, ok := typeSchemas[f.Type]
	if !ok {
		return nil, invalid(ReasonUnknownType, "type", nil)
	}
	if err := validateType(&f, ts); err != nil {
		return nil, err
	}
	if err := Canonicalize(&f); err != nil {
		return nil, err
	}
	if err := validateMutationSlots(&f, ts); err != nil {
		return nil, err
	}
	return &f, nil
}

// envelopeKeys is the closed set of top-level finding fields.
var envelopeKeys = map[string]bool{
	"finding_id": true, "type": true, "target": true, "auth": true,
	"evidence": true, "proof": true, "controls": true,
	"mutation_slots": true, "side_effects": true,
}

// validateEnvelope enforces the top-level field set: strict keys, required
// fields, a real target/auth, and an evidence object that is not prose.
func validateEnvelope(raw []byte) error {
	m, err := decodeObject(raw)
	if err != nil {
		return invalid(ReasonMalformedJSON, "", err)
	}
	for k := range m {
		if !envelopeKeys[k] {
			return invalid(ReasonUnknownField, k, nil)
		}
	}
	for _, k := range []string{"finding_id", "type", "target", "evidence", "proof"} {
		if _, ok := m[k]; !ok {
			return invalid(ReasonMissingField, k, nil)
		}
	}
	if err := requireNonEmptyString(m["finding_id"], "finding_id"); err != nil {
		return err
	}
	if err := requireNonEmptyString(m["type"], "type"); err != nil {
		return err
	}
	if err := validateTarget(m["target"]); err != nil {
		return err
	}
	if a, ok := m["auth"]; ok {
		if err := validateAuth(a); err != nil {
			return err
		}
	}
	// Evidence must be a non-empty object; a prose string or {} proves nothing.
	ev, err := decodeObject(m["evidence"])
	if err != nil || len(ev) == 0 {
		return invalid(ReasonProseOnly, "evidence", err)
	}
	if _, err := decodeObject(m["proof"]); err != nil {
		return invalid(ReasonWrongType, "proof", err)
	}
	return nil
}

// targetSchema is strict: the struct is fixed, so an unknown key is a typo.
var targetSchema = objSchema{strict: true, fields: []field{
	req("expected_origin", fString),
	req("allowed_hosts", fArray),
	req("allowed_schemes", fArray),
	opt("scope_id", fString),
	opt("allowed_ports", fArray),
}}

func validateTarget(raw json.RawMessage) error {
	if err := checkObject(raw, targetSchema, "target"); err != nil {
		return err
	}
	var t Target
	if err := json.Unmarshal(raw, &t); err != nil {
		return invalid(ReasonWrongType, "target", err)
	}
	if t.ExpectedOrigin == "" {
		return invalid(ReasonMissingField, "target.expected_origin", nil)
	}
	if len(t.AllowedHosts) == 0 {
		return invalid(ReasonMissingField, "target.allowed_hosts", nil)
	}
	if len(t.AllowedSchemes) == 0 {
		return invalid(ReasonMissingField, "target.allowed_schemes", nil)
	}
	return nil
}

var authKeys = map[string]bool{"required": true, "auth_state_id": true, "role": true}

// validateAuth keeps raw credentials out: only the three reference fields are
// allowed, and a required auth must name an auth_state_id.
func validateAuth(raw json.RawMessage) error {
	m, err := decodeObject(raw)
	if err != nil {
		return invalid(ReasonWrongType, "auth", err)
	}
	for k := range m {
		if !authKeys[k] {
			return invalid(ReasonInlinedCredential, joinField("auth", k), nil)
		}
	}
	var a AuthRef
	if err := json.Unmarshal(raw, &a); err != nil {
		return invalid(ReasonWrongType, "auth", err)
	}
	if a.Required && a.AuthStateID == "" {
		return invalid(ReasonMissingField, "auth.auth_state_id", nil)
	}
	return nil
}

// validateType checks the evidence/proof shape and that every declared request
// exists and is well-formed.
func validateType(f *Finding, ts typeSchema) error {
	if err := checkObject(f.Evidence, ts.evidence, "evidence"); err != nil {
		return err
	}
	if err := checkObject(f.Proof, ts.proof, "proof"); err != nil {
		return err
	}
	m, err := decodeObject(f.Evidence)
	if err != nil {
		return invalid(ReasonWrongType, "evidence", err)
	}
	for _, p := range ts.requests {
		raw, ok := resolvePath(m, strings.Split(p, "."))
		if !ok {
			return invalid(ReasonMissingField, joinField("evidence", p), nil)
		}
		if err := checkRequest(raw, joinField("evidence", p)); err != nil {
			return err
		}
	}
	for _, p := range ts.requestArrays {
		raw, ok := m[p]
		if !ok {
			return invalid(ReasonMissingField, joinField("evidence", p), nil)
		}
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil || len(arr) == 0 {
			return invalid(ReasonBadRequest, joinField("evidence", p), nil)
		}
		for i, r := range arr {
			if err := checkRequest(r, fmt.Sprintf("evidence.%s[%d]", p, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateMutationSlots verifies every slot points at a real position in the
// finding's requests; a dangling slot makes the finding invalid.
func validateMutationSlots(f *Finding, ts typeSchema) error {
	if len(f.Mutation) == 0 {
		return nil
	}
	reqs := evidenceRequests(f, ts)
	for name, loc := range f.Mutation {
		if !slotResolves(strings.TrimSpace(loc), reqs) {
			return invalid(ReasonDanglingSlot, name, nil)
		}
	}
	return nil
}

// slotResolves reports whether loc names a real position in some request.
// Forms: "query:<param>", "header:<name>", "body:<token>", a JSON pointer
// "/a/b" into a body, or a bare token appearing verbatim in a URL or body.
func slotResolves(loc string, reqs []Request) bool {
	switch {
	case loc == "":
		return false
	case strings.HasPrefix(loc, "query:"):
		return anyQueryParam(reqs, loc[len("query:"):])
	case strings.HasPrefix(loc, "header:"):
		return anyHeader(reqs, loc[len("header:"):])
	case strings.HasPrefix(loc, "body:"):
		return anyBodyContains(reqs, loc[len("body:"):])
	case strings.HasPrefix(loc, "/"):
		return anyPointer(reqs, loc)
	default:
		return anyContains(reqs, loc)
	}
}

func anyQueryParam(reqs []Request, param string) bool {
	for _, r := range reqs {
		u, err := url.Parse(r.URL)
		if err != nil {
			continue
		}
		if _, ok := u.Query()[param]; ok {
			return true
		}
	}
	return false
}

func anyHeader(reqs []Request, name string) bool {
	for _, r := range reqs {
		for _, h := range r.Headers {
			if strings.EqualFold(h.Name, name) {
				return true
			}
		}
	}
	return false
}

func anyBodyContains(reqs []Request, token string) bool {
	for _, r := range reqs {
		if strings.Contains(r.Body, token) {
			return true
		}
	}
	return false
}

// anyContains matches a bare token (or its {{token}} form) in a URL or body.
func anyContains(reqs []Request, token string) bool {
	braced := "{{" + token + "}}"
	for _, r := range reqs {
		if strings.Contains(r.URL, token) || strings.Contains(r.Body, token) ||
			strings.Contains(r.URL, braced) || strings.Contains(r.Body, braced) {
			return true
		}
	}
	return false
}

// anyPointer reports whether a JSON pointer resolves in any request body.
func anyPointer(reqs []Request, pointer string) bool {
	for _, r := range reqs {
		if r.Body == "" {
			continue
		}
		var doc any
		if json.Unmarshal([]byte(r.Body), &doc) != nil {
			continue
		}
		if pointerResolves(doc, pointer) {
			return true
		}
	}
	return false
}

// pointerResolves walks an RFC 6901 JSON pointer through a decoded body.
func pointerResolves(doc any, pointer string) bool {
	if pointer == "/" {
		return true
	}
	cur := doc
	for _, tok := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(node) {
				return false
			}
			cur = node[i]
		default:
			return false
		}
	}
	return true
}

// requireNonEmptyString checks raw is a non-empty JSON string.
func requireNonEmptyString(raw json.RawMessage, where string) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return invalid(ReasonWrongType, where, err)
	}
	if strings.TrimSpace(s) == "" {
		return invalid(ReasonMissingField, where, nil)
	}
	return nil
}

// rejectInlinedCredential blocks raw credential headers; auth must come from an
// auth_state_id reference, never inlined.
func rejectInlinedCredential(headers []Header, where string) error {
	for _, h := range headers {
		switch strings.ToLower(strings.TrimSpace(h.Name)) {
		case "cookie", "authorization", "proxy-authorization":
			return invalid(ReasonInlinedCredential, where, nil)
		}
	}
	return nil
}
