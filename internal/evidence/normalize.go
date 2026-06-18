package evidence

import (
	"encoding/json"
	"net/textproto"
	"net/url"
	"strings"
)

// Canonicalize rewrites a Finding into replay-safe form: request URLs get a
// lower-cased scheme/host (trailing dot stripped) and canonical header casing.
// Everything else is preserved. Security canonicalization (IDNA, scope, DNS)
// is the policy gate's job, not this one.
func Canonicalize(f *Finding) error {
	if ts, ok := typeSchemas[f.Type]; ok && len(f.Evidence) > 0 {
		if m, err := decodeObject(f.Evidence); err == nil {
			for _, p := range ts.requests {
				if err := rewriteRequest(m, strings.Split(p, ".")); err != nil {
					return err
				}
			}
			for _, p := range ts.requestArrays {
				if err := rewriteRequestArray(m, p); err != nil {
					return err
				}
			}
			b, err := json.Marshal(m)
			if err != nil {
				return invalid(ReasonWrongType, "evidence", err)
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

// canonicalizeRequest lower-cases the URL scheme/host and header names in place.
func canonicalizeRequest(r *Request) error {
	if r.URL != "" {
		u, err := url.Parse(r.URL)
		if err != nil {
			return invalid(ReasonBadURL, "url", err)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		u.Host = rebuildHost(host, u.Port())
		r.URL = u.String()
	}
	for i := range r.Headers {
		r.Headers[i].Name = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(r.Headers[i].Name))
	}
	return nil
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

// rewriteRequest canonicalizes the request object at a dotted path inside an
// evidence map, re-marshaling each level it descends through.
func rewriteRequest(m map[string]json.RawMessage, parts []string) error {
	raw, ok := m[parts[0]]
	if !ok {
		return nil
	}
	if len(parts) == 1 {
		var r Request
		if err := json.Unmarshal(raw, &r); err != nil {
			return invalid(ReasonBadRequest, parts[0], err)
		}
		if err := canonicalizeRequest(&r); err != nil {
			return err
		}
		b, err := json.Marshal(r)
		if err != nil {
			return invalid(ReasonWrongType, parts[0], err)
		}
		m[parts[0]] = b
		return nil
	}
	child, err := decodeObject(raw)
	if err != nil {
		return invalid(ReasonWrongType, parts[0], err)
	}
	if err := rewriteRequest(child, parts[1:]); err != nil {
		return err
	}
	b, err := json.Marshal(child)
	if err != nil {
		return invalid(ReasonWrongType, parts[0], err)
	}
	m[parts[0]] = b
	return nil
}

// rewriteRequestArray canonicalizes every request in a top-level array field.
func rewriteRequestArray(m map[string]json.RawMessage, path string) error {
	raw, ok := m[path]
	if !ok {
		return nil
	}
	var arr []Request
	if err := json.Unmarshal(raw, &arr); err != nil {
		return invalid(ReasonBadRequest, path, err)
	}
	for i := range arr {
		if err := canonicalizeRequest(&arr[i]); err != nil {
			return err
		}
	}
	b, err := json.Marshal(arr)
	if err != nil {
		return invalid(ReasonWrongType, path, err)
	}
	m[path] = b
	return nil
}

// evidenceRequests gathers every request the finding declares, so slot
// locations can be checked against real positions.
func evidenceRequests(f *Finding, ts typeSchema) []Request {
	var reqs []Request
	if m, err := decodeObject(f.Evidence); err == nil {
		for _, p := range ts.requests {
			if raw, ok := resolvePath(m, strings.Split(p, ".")); ok {
				var r Request
				if json.Unmarshal(raw, &r) == nil {
					reqs = append(reqs, r)
				}
			}
		}
		for _, p := range ts.requestArrays {
			if raw, ok := m[p]; ok {
				var arr []Request
				if json.Unmarshal(raw, &arr) == nil {
					reqs = append(reqs, arr...)
				}
			}
		}
	}
	reqs = append(reqs, f.Controls...)
	reqs = append(reqs, f.SideEffects.Cleanup...)
	return reqs
}

// resolvePath walks a dotted path through nested JSON objects.
func resolvePath(m map[string]json.RawMessage, parts []string) (json.RawMessage, bool) {
	raw, ok := m[parts[0]]
	if !ok {
		return nil, false
	}
	if len(parts) == 1 {
		return raw, true
	}
	child, err := decodeObject(raw)
	if err != nil {
		return nil, false
	}
	return resolvePath(child, parts[1:])
}
