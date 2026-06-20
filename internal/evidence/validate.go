package evidence

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// Stable reason codes for an invalid finding.
const (
	ReasonEmptyBody         = "empty_body"
	ReasonMalformedJSON     = "malformed_json"
	ReasonMissingField      = "missing_field"
	ReasonUnknownType       = "unknown_type"
	ReasonSchemaViolation   = "schema_violation"
	ReasonInlinedCredential = "inlined_credential" //nolint:gosec // G101 false positive: a reason code, not a secret
	ReasonBadURL            = "bad_url"
	ReasonDanglingSlot      = "dangling_mutation_slot"
)

// InvalidError unwraps to ErrInvalid.
// Reason is the report code, cause the JSON path.
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

// Parse: untrusted JSON -> validated Finding.
// Schema, reject inlined credentials,
// canonicalize, check slots.
// Fail-closed: no execution.
func Parse(raw []byte) (*Finding, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, invalid(ReasonEmptyBody, "", nil)
	}

	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return nil, invalid(ReasonMalformedJSON, "", err)
	}
	obj, ok := instance.(map[string]any)
	if !ok {
		return nil, invalid(ReasonMalformedJSON, "", nil)
	}

	typ, _ := obj["type"].(string)
	if strings.TrimSpace(typ) == "" {
		return nil, invalid(ReasonMissingField, "type", nil)
	}
	if !hasSchema(typ) {
		return nil, invalid(ReasonUnknownType, "type", nil)
	}

	// Reject inlined credentials first:
	// security, not shape.
	if name, found := findInlinedCredential(instance); found {
		return nil, invalid(ReasonInlinedCredential, name, nil)
	}

	if err := validateInstance(typ, instance); err != nil {
		return nil, invalid(ReasonSchemaViolation, "", err)
	}

	var f Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, invalid(ReasonSchemaViolation, "", err)
	}
	if err := Canonicalize(&f); err != nil {
		return nil, err
	}
	if err := validateMutationSlots(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// findInlinedCredential finds cookie/auth headers.
// They must reference auth_state_id, not inline it.
func findInlinedCredential(v any) (string, bool) {
	switch t := v.(type) {
	case map[string]any:
		if hs, ok := t["headers"].([]any); ok {
			for _, h := range hs {
				hm, ok := h.(map[string]any)
				if !ok {
					continue
				}
				name, _ := hm["name"].(string)
				switch strings.ToLower(strings.TrimSpace(name)) {
				case "cookie", "authorization", "proxy-authorization":
					return name, true
				}
			}
		}
		for _, val := range t {
			if name, found := findInlinedCredential(val); found {
				return name, true
			}
		}
	case []any:
		for _, val := range t {
			if name, found := findInlinedCredential(val); found {
				return name, true
			}
		}
	}
	return "", false
}

// validateMutationSlots rejects unreal positions.
func validateMutationSlots(f *Finding) error {
	if len(f.Mutation) == 0 {
		return nil
	}
	reqs := ExtractRequests(f)
	for name, loc := range f.Mutation {
		if !slotResolves(strings.TrimSpace(loc), reqs) {
			return invalid(ReasonDanglingSlot, name, nil)
		}
	}
	return nil
}

// slotResolves reports if loc is a real position.
func slotResolves(loc string, reqs []Request) bool {
	switch {
	case loc == "":
		return false
	case strings.HasPrefix(loc, "query:"):
		param := loc[len("query:"):]
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
	case strings.HasPrefix(loc, "header:"):
		name := loc[len("header:"):]
		for _, r := range reqs {
			for _, h := range r.Headers {
				if strings.EqualFold(h.Name, name) {
					return true
				}
			}
		}
		return false
	case strings.HasPrefix(loc, "body:"):
		token := loc[len("body:"):]
		for _, r := range reqs {
			if strings.Contains(r.Body, token) {
				return true
			}
		}
		return false
	case strings.HasPrefix(loc, "/"):
		return anyPointer(reqs, loc)
	default:
		return anyContains(reqs, loc)
	}
}

// anyContains matches token/{{token}} in URL/body.
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

// anyPointer reports if a pointer resolves in body.
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

// pointerResolves walks an RFC 6901 JSON pointer
// through a body.
func pointerResolves(doc any, pointer string) bool {
	if pointer == "/" {
		return true
	}
	cur := doc
	for tok := range strings.SplitSeq(strings.TrimPrefix(pointer, "/"), "/") {
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
