package evidence

import (
	"encoding/json"
	"net/textproto"
	"net/url"
	"strings"
)

// Canonicalize rewrites a Finding into replay-safe form: every request URL gets a
// lower-cased scheme/host (trailing dot stripped) and canonical header casing.
// Request objects are found structurally (any object with method+url), so no
// per-type metadata is needed. Everything else is preserved.
func Canonicalize(f *Finding) error {
	if len(f.Evidence) > 0 {
		var v any
		if err := json.Unmarshal(f.Evidence, &v); err == nil {
			if err := canonicalizeValue(v); err != nil {
				return err
			}
			b, err := json.Marshal(v)
			if err != nil {
				return invalid(ReasonSchemaViolation, "evidence", err)
			}
			f.Evidence = b
		}
	}
	for i := range f.Controls {
		if err := canonicalizeRequest(&f.Controls[i]); err != nil {
			return err
		}
	}
	for i := range f.SideEffects.Cleanup {
		if err := canonicalizeRequest(&f.SideEffects.Cleanup[i]); err != nil {
			return err
		}
	}
	return nil
}

// canonicalizeValue walks a decoded JSON tree and canonicalizes every
// request-shaped object in place.
func canonicalizeValue(v any) error {
	switch t := v.(type) {
	case map[string]any:
		if isRequestShape(t) {
			if err := canonicalizeRequestMap(t); err != nil {
				return err
			}
		}
		for _, child := range t {
			if err := canonicalizeValue(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := canonicalizeValue(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// isRequestShape reports whether a decoded object is a request (has string
// method and url).
func isRequestShape(m map[string]any) bool {
	_, hasMethod := m["method"].(string)
	_, hasURL := m["url"].(string)
	return hasMethod && hasURL
}

// canonicalizeRequestMap canonicalizes the url and header names of a decoded
// request object in place.
func canonicalizeRequestMap(m map[string]any) error {
	if raw, ok := m["url"].(string); ok && raw != "" {
		canon, err := canonicalURL(raw)
		if err != nil {
			return err
		}
		m["url"] = canon
	}
	if hs, ok := m["headers"].([]any); ok {
		for _, h := range hs {
			if hm, ok := h.(map[string]any); ok {
				if name, ok := hm["name"].(string); ok {
					hm["name"] = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
				}
			}
		}
	}
	return nil
}

// canonicalizeRequest lower-cases the URL scheme/host and header names of a typed
// request in place.
func canonicalizeRequest(r *Request) error {
	if r.URL != "" {
		canon, err := canonicalURL(r.URL)
		if err != nil {
			return err
		}
		r.URL = canon
	}
	for i := range r.Headers {
		r.Headers[i].Name = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(r.Headers[i].Name))
	}
	return nil
}

// canonicalURL lower-cases the scheme and host (stripping a trailing dot),
// preserving path, query, and port.
func canonicalURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", invalid(ReasonBadURL, "url", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	u.Host = rebuildHost(host, u.Port())
	return u.String(), nil
}

// rebuildHost reassembles a host[:port] authority, bracketing IPv6 literals.
func rebuildHost(host, port string) string {
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") { // IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// ExtractRequests returns every request a finding declares (in evidence,
// controls, and cleanup) for external use such as policy checking. Requests are
// found structurally, so the set does not depend on the finding type.
func ExtractRequests(f *Finding) []Request {
	var reqs []Request
	if len(f.Evidence) > 0 {
		var v any
		if json.Unmarshal(f.Evidence, &v) == nil {
			collectRequests(v, &reqs)
		}
	}
	reqs = append(reqs, f.Controls...)
	reqs = append(reqs, f.SideEffects.Cleanup...)
	return reqs
}

// collectRequests gathers every request-shaped object in a decoded JSON tree.
func collectRequests(v any, out *[]Request) {
	switch t := v.(type) {
	case map[string]any:
		if isRequestShape(t) {
			if b, err := json.Marshal(t); err == nil {
				var r Request
				if json.Unmarshal(b, &r) == nil {
					*out = append(*out, r)
				}
			}
		}
		for _, child := range t {
			collectRequests(child, out)
		}
	case []any:
		for _, child := range t {
			collectRequests(child, out)
		}
	}
}
