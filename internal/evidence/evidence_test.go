package evidence

import (
	"encoding/json"
	"errors"
	"testing"
)

// validPathTraversal is a well-formed finding reused across accept tests. The
// request host is deliberately mixed-case to exercise canonicalization.
const validPathTraversal = `{
  "finding_id": "pt-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"],
    "allowed_ports": [443]
  },
  "auth": {"required": false},
  "evidence": {
    "request": {"method": "GET", "url": "https://APP.Example.com/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["VERIFIER_CANARY_FILE_2026"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

func mustParse(t *testing.T, raw string) *Finding {
	t.Helper()
	f, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	return f
}

func assertInvalid(t *testing.T, raw, wantReason string) {
	t.Helper()
	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatalf("expected invalid, got nil error")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error does not wrap ErrInvalid: %v", err)
	}
	var ie *InvalidError
	if !errors.As(err, &ie) {
		t.Fatalf("expected *InvalidError, got %T: %v", err, err)
	}
	if wantReason != "" && ie.Reason != wantReason {
		t.Fatalf("reason = %q, want %q (err: %v)", ie.Reason, wantReason, err)
	}
}

func TestParseAcceptsValidFindings(t *testing.T) {
	cases := map[string]string{
		"path_traversal": validPathTraversal,

		"xss.reflected (browser entrypoint + trigger)": `{
  "finding_id": "x-1", "type": "xss.reflected",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "entrypoint": {"method": "GET", "url": "https://app.example.com/search?q=VERIFIER_XSS_{{nonce}}"},
    "payload_marker": "VERIFIER_XSS_{{nonce}}",
    "trigger": {"kind": "browser_navigate", "wait": "load_or_network_idle"},
    "vulnerable_parameter": "q"
  },
  "proof": {"accepted_signals": ["javascript_dialog"], "expected_message_contains": "VERIFIER_XSS_", "expected_execution_origin": "https://app.example.com"}
}`,

		"xss.stored (setup array + trigger)": `{
  "finding_id": "xs-1", "type": "xss.stored",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "setup": [{"method": "POST", "url": "https://app.example.com/profile", "body": "display_name=VERIFIER_STORED_XSS_{{nonce}}"}],
    "trigger": {"method": "GET", "url": "https://app.example.com/profile/view"},
    "vulnerable_parameter": "display_name",
    "payload_marker": "VERIFIER_STORED_XSS_{{nonce}}"
  },
  "proof": {"accepted_signals": ["javascript_dialog"], "expected_message_contains": "VERIFIER_STORED_XSS_", "expected_execution_origin": "https://app.example.com", "timeout_ms": 5000}
}`,

		"sqli.time_based (base_request + injection)": `{
  "finding_id": "sq-1", "type": "sqli.time_based",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "base_request": {"method": "GET", "url": "https://app.example.com/item?id=1"},
    "injection": {
      "location": {"kind": "query", "name": "id"},
      "payloads": {
        "control": "1",
        "delay_low": "1';SELECT pg_sleep(1)--",
        "delay_high": "1';SELECT pg_sleep(5)--"
      }
    }
  },
  "proof": {"min_median_delta_ms": 3000, "repetitions": 3}
}`,

		"ssrf.oast (injection_location)": `{
  "finding_id": "ss-1", "type": "ssrf.oast",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "request": {"method": "POST", "url": "https://app.example.com/fetch", "body": "{\"url\":\"https://placeholder\"}"},
    "injection_location": {"kind": "json_body", "json_pointer": "/url"},
    "expected_protocols": ["dns", "http"]
  },
  "proof": {"expected_signal": "oast_interaction", "poll_window_seconds": 30}
}`,

		"xss.blind (request + mutation slot)": `{
  "finding_id": "xb-1", "type": "xss.blind",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "request": {"method": "POST", "url": "https://app.example.com/contact", "body": "message=placeholder"},
    "mutation_slots": {"oast_url": "message"}
  },
  "proof": {"expected_signal": "oast_http", "expected_path_contains": "/c", "poll_window_seconds": 900}
}`,

		"idor.read (two roles)": `{
  "finding_id": "id-1", "type": "idor.read",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "resource_owner_auth_state_id": "owner-session",
    "attacker_auth_state_id": "attacker-session",
    "setup_resource": {"method": "POST", "url": "https://app.example.com/notes", "body": "title=canary-{{nonce}}"},
    "attack_request": {"method": "GET", "url": "https://app.example.com/notes/{{created_resource_id}}"}
  },
  "proof": {"expected_marker": "canary-{{nonce}}", "require_owner_control": true}
}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			f := mustParse(t, raw)
			if f.Type == "" {
				t.Fatal("parsed finding has empty type")
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name, raw, wantReason string
	}{
		{"empty body", ``, ReasonEmptyBody},
		{"whitespace body", "   \n  ", ReasonEmptyBody},
		{"malformed json", `{ not json `, ReasonMalformedJSON},
		{"unknown top-level field", `{"finding_id":"a","type":"path_traversal.file_read","target":{},"evidence":{},"proof":{},"surprise":1}`, ReasonSchemaViolation},
		{"missing type", `{"finding_id":"a","target":{},"evidence":{},"proof":{}}`, ReasonMissingField},
		{"empty finding_id", `{"finding_id":"","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"x":1},"proof":{}}`, ReasonSchemaViolation},
		{
			"prose-only evidence",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":"I think this is vulnerable","proof":{}}`,
			ReasonSchemaViolation,
		},
		{
			"empty evidence object",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{},"proof":{}}`,
			ReasonSchemaViolation,
		},
		{
			"unknown vulnerability type",
			`{"finding_id":"a","type":"telepathy.injection","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"x":1},"proof":{}}`,
			ReasonUnknownType,
		},
		{
			"target missing allowed_hosts",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_schemes":["https"]},"evidence":{"x":1},"proof":{}}`,
			ReasonSchemaViolation,
		},
		{
			"target empty allowed_hosts",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":[],"allowed_schemes":["https"]},"evidence":{"x":1},"proof":{}}`,
			ReasonSchemaViolation,
		},
		{
			"auth carries inlined cookie (unknown auth key)",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"auth":{"required":true,"cookie":"session=abc"},"evidence":{"x":1},"proof":{}}`,
			ReasonSchemaViolation,
		},
		{
			"auth required without auth_state_id",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"auth":{"required":true},"evidence":{"x":1},"proof":{}}`,
			ReasonSchemaViolation,
		},
		{
			"missing required evidence field",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"request":{"method":"GET","url":"https://a/x"}},"proof":{"require_marker":true,"require_negative_control_absent":true}}`,
			ReasonSchemaViolation,
		},
		{
			"unknown evidence field (strict)",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"request":{"method":"GET","url":"https://a/x"},"vulnerable_parameter":"file","expected_markers":["M"],"negative_control":{"method":"GET","url":"https://a/y"},"extra":1},"proof":{"require_marker":true,"require_negative_control_absent":true}}`,
			ReasonSchemaViolation,
		},
		{
			"evidence request missing url",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"request":{"method":"GET"},"vulnerable_parameter":"file","expected_markers":["M"],"negative_control":{"method":"GET","url":"https://a/y"}},"proof":{"require_marker":true,"require_negative_control_absent":true}}`,
			ReasonSchemaViolation,
		},
		{
			"evidence request inlines authorization header",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"request":{"method":"GET","url":"https://a/x","headers":[{"name":"Authorization","value":"Bearer x"}]},"vulnerable_parameter":"file","expected_markers":["M"],"negative_control":{"method":"GET","url":"https://a/y"}},"proof":{"require_marker":true,"require_negative_control_absent":true}}`,
			ReasonInlinedCredential,
		},
		{
			"proof field wrong type",
			`{"finding_id":"a","type":"path_traversal.file_read","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"request":{"method":"GET","url":"https://a/x"},"vulnerable_parameter":"file","expected_markers":["M"],"negative_control":{"method":"GET","url":"https://a/y"}},"proof":{"require_marker":"yes","require_negative_control_absent":true}}`,
			ReasonSchemaViolation,
		},
		{
			"empty setup array",
			`{"finding_id":"a","type":"xss.stored","target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},"evidence":{"setup":[],"trigger":{"method":"GET","url":"https://a/v"},"vulnerable_parameter":"n","payload_marker":"M"},"proof":{"accepted_signals":["javascript_dialog"],"expected_message_contains":"M","expected_execution_origin":"https://a","timeout_ms":1}}`,
			ReasonSchemaViolation,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertInvalid(t, tc.raw, tc.wantReason)
		})
	}
}

// Canonicalization lower-cases the request scheme/host (preserving path + query)
// and canonicalizes header names, in place inside the per-type evidence.
func TestCanonicalizeLowercasesEvidenceRequests(t *testing.T) {
	f := mustParse(t, validPathTraversal)

	var ev struct {
		Request struct {
			URL string `json:"url"`
		} `json:"request"`
	}
	if err := json.Unmarshal(f.Evidence, &ev); err != nil {
		t.Fatalf("evidence not an object: %v", err)
	}
	const want = "https://app.example.com/download?file=../../etc/passwd"
	if ev.Request.URL != want {
		t.Fatalf("canonical url = %q, want %q", ev.Request.URL, want)
	}
}

func TestCanonicalizeHeaderNames(t *testing.T) {
	r := Request{URL: "https://APP.example.com/", Headers: []Header{{Name: "x-trace-id", Value: "1"}}}
	if err := canonicalizeRequest(&r); err != nil {
		t.Fatalf("canonicalizeRequest: %v", err)
	}
	if r.URL != "https://app.example.com/" {
		t.Fatalf("url = %q", r.URL)
	}
	if r.Headers[0].Name != "X-Trace-Id" {
		t.Fatalf("header name = %q, want X-Trace-Id", r.Headers[0].Name)
	}
}

// A userinfo/punycode URL in evidence is not the evidence layer's job to reject
// (that is the policy gate); canonicalization must handle it without erroring.
func TestCanonicalizeToleratesAdversarialURLs(t *testing.T) {
	for _, raw := range []string{
		"https://example.com@evil.com/",
		"https://xn--e1afmkfd.xn--p1ai/path",
		"http://169.254.169.254/latest/meta-data",
	} {
		r := Request{URL: raw}
		if err := canonicalizeRequest(&r); err != nil {
			t.Fatalf("canonicalizeRequest(%q): %v", raw, err)
		}
	}
}

func TestMutationSlotResolution(t *testing.T) {
	reqs := []Request{{
		Method:  "POST",
		URL:     "https://app.example.com/fetch?file=x&cb=1",
		Headers: []Header{{Name: "X-Trace", Value: "t"}},
		Body:    `{"target":{"url":"VERIFIER_{{nonce}}"}}`,
	}}

	cases := []struct {
		loc  string
		want bool
	}{
		{"query:cb", true},
		{"query:file", true},
		{"query:missing", false},
		{"header:X-Trace", true},
		{"header:x-trace", true}, // case-insensitive
		{"header:Cookie", false},
		{"body:VERIFIER_", true},
		{"body:absent", false},
		{"/target/url", true},
		{"/target/missing", false},
		{"nonce", true}, // bare token matches {{nonce}} placeholder in body
		{"absent_token", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.loc, func(t *testing.T) {
			if got := slotResolves(tc.loc, reqs); got != tc.want {
				t.Fatalf("slotResolves(%q) = %v, want %v", tc.loc, got, tc.want)
			}
		})
	}
}

// A declared slot that points at a real query parameter is accepted; a dangling
// one makes the finding invalid.
func TestParseMutationSlots(t *testing.T) {
	resolving := `{
  "finding_id": "m-1", "type": "path_traversal.file_read",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com/download?file=../../etc/passwd&cb=0"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true},
  "mutation_slots": {"cachebuster": "query:cb"}
}`
	mustParse(t, resolving)

	dangling := `{
  "finding_id": "m-2", "type": "path_traversal.file_read",
  "target": {"expected_origin": "https://app.example.com", "allowed_hosts": ["app.example.com"], "allowed_schemes": ["https"]},
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com/download?file=x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true},
  "mutation_slots": {"cachebuster": "query:does_not_exist"}
}`
	assertInvalid(t, dangling, ReasonDanglingSlot)
}

// Every type's example must declare at least one request, so the canonicalizer
// and replay have something to operate on.
func TestEveryTypeHasRequests(t *testing.T) {
	for _, typ := range schemaTypes() {
		doc, _ := schemaDoc(typ)
		var d struct {
			Examples []json.RawMessage `json:"examples"`
		}
		if json.Unmarshal(doc, &d) != nil || len(d.Examples) == 0 {
			t.Errorf("%s: no example", typ)
			continue
		}
		f, err := Parse(d.Examples[0])
		if err != nil {
			t.Errorf("%s: example does not parse: %v", typ, err)
			continue
		}
		if len(ExtractRequests(f)) == 0 {
			t.Errorf("type %q example declares no requests", typ)
		}
	}
}
