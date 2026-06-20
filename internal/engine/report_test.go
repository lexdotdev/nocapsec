package engine

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TestReportShapeConsistency verifies that every verdict produces a Report with
// the required fields set and omitted fields correct for that verdict.
func TestReportShapeConsistency(t *testing.T) {
	// Stand up a target for the verified case.
	const marker = "VERIFIED_MARKER"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			_, _ = w.Write([]byte(marker))
			return
		}
		_, _ = w.Write([]byte("clean"))
	}))
	defer target.Close()

	ip, port := serverAddr(t, target)
	portStr := strconv.Itoa(port)
	resolver := fakeResolver{ips: []net.IP{ip}}

	cases := []struct {
		name    string
		finding string
		want    verdict.Verdict
		// requireProof says this verdict must carry a non-empty proof block.
		requireProof bool
		// requireReason says this verdict must carry a non-empty reason code.
		requireReason bool
	}{
		{
			name:          "invalid: malformed JSON",
			finding:       `not json`,
			want:          verdict.Invalid,
			requireReason: true,
		},
		{
			name: "invalid: unknown type",
			finding: `{"finding_id":"x","type":"magic.vuln",
				"target":{"expected_origin":"https://a","allowed_hosts":["a"],"allowed_schemes":["https"]},
				"evidence":{"x":1},"proof":{}}`,
			want:          verdict.Invalid,
			requireReason: true,
		},
		{
			name: "rejected: out-of-scope host",
			finding: `{
  "finding_id": "rs-1",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"],
    "allowed_ports": [443]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://evil.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
			want:          verdict.Rejected,
			requireReason: true,
		},
		{
			name: "verified: marker present",
			finding: `{
  "finding_id": "rs-v",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["` + marker + `"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
			want:         verdict.Verified,
			requireProof: true,
		},
		{
			name: "not_reproduced: marker absent",
			finding: `{
  "finding_id": "rs-nr",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["ABSENT_MARKER"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
			want: verdict.NotReproduced,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := New(Config{Resolver: resolver, InternalAssessment: true})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = e.Close() }()

			report, verErr := e.Verify(context.Background(), []byte(tc.finding))
			if verErr != nil {
				t.Fatalf("Verify: %v", verErr)
			}
			if report.Verdict != tc.want {
				t.Fatalf("verdict = %q, want %q (reason=%q)", report.Verdict, tc.want, report.Reason)
			}

			// Every report must have DecidedAt stamped.
			if report.DecidedAt.IsZero() {
				t.Fatal("DecidedAt not stamped")
			}

			// Reports with reason-bearing verdicts must have a Reason.
			if tc.requireReason && report.Reason == "" {
				t.Fatal("reason empty for verdict that requires it")
			}

			// Verified reports must carry a non-empty proof block.
			if tc.requireProof && len(report.Proof) == 0 {
				t.Fatal("proof empty for verdict that requires it")
			}

			// Marshal round-trip: the report must be valid JSON.
			b, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatalf("JSON: %v", marshalErr)
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(b, &m) != nil {
				t.Fatalf("report is not valid JSON: %s", b)
			}

			// Required keys always present.
			for _, k := range []string{"finding_id", "type", "verdict", "decided_at"} {
				if _, ok := m[k]; !ok {
					t.Errorf("missing key %q in report JSON", k)
				}
			}
		})
	}
}

// TestRedactionAudit checks that no stored artifact or report JSON contains raw
// credentials (Cookie, Authorization, Set-Cookie, CSRF, bearer values).
func TestRedactionAudit(t *testing.T) {
	const marker = "AUDIT_CANARY"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back a "sensitive" response with headers that should be redacted.
		w.Header().Set("Set-Cookie", "session=topsecret; Path=/")
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			_, _ = w.Write([]byte(marker))
			return
		}
		_, _ = w.Write([]byte("clean"))
	}))
	defer target.Close()

	ip, port := serverAddr(t, target)
	portStr := strconv.Itoa(port)
	resolver := fakeResolver{ips: []net.IP{ip}}
	store := artifacts.NewStore()

	finding := `{
  "finding_id": "redact-audit",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://app.example.com:` + portStr + `",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["http"],
    "allowed_ports": [` + portStr + `]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=../../etc/passwd"},
    "vulnerable_parameter": "file",
    "expected_markers": ["` + marker + `"],
    "negative_control": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`

	e, err := New(Config{Resolver: resolver, Store: store, InternalAssessment: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = e.Close() }()

	report, err := e.Verify(context.Background(), []byte(finding))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Check the report JSON itself.
	reportJSON, _ := json.Marshal(report)
	assertNoSecrets(t, "report_json", string(reportJSON))

	// Also store some data with sensitive headers and verify it's redacted.
	sensitiveData := "Cookie: session=secretvalue\nAuthorization: Bearer eyJtoken\nSet-Cookie: id=val\ncsrf_token=abc123\nX-CSRF-TOKEN=xyz789"
	ref, err := store.Put(context.Background(), "redact-audit", artifacts.KindHTTPExchange, []byte(sensitiveData))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, err := store.Get(context.Background(), ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertNoSecrets(t, "stored_artifact", string(data))
}

// sensitivePatterns are tokens that must never appear in a stored artifact or
// report, proving the redaction pipeline covers Cookie, Authorization,
// Set-Cookie, CSRF, and bearer values.
var sensitivePatterns = []string{
	"secretvalue",
	"eyJtoken",
	"id=val",
	"abc123",
	"xyz789",
}

func assertNoSecrets(t *testing.T, label, s string) {
	t.Helper()
	for _, pat := range sensitivePatterns {
		if strings.Contains(s, pat) {
			t.Errorf("[%s] found secret %q in output", label, pat)
		}
	}
}
