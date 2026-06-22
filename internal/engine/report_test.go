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

// Reports keep required shape.
func TestReportShapeConsistency(t *testing.T) {
	// Target for verified case.
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
		// requireProof expects proof.
		requireProof bool
		// requireReason expects reason.
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
    "base_request": {"method": "GET", "url": "https://evil.com/x?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
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
    "base_request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "` + marker + `", "repetitions": 2}
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
    "base_request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "ABSENT_MARKER", "repetitions": 2}
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

			// Every report has DecidedAt.
			if report.DecidedAt.IsZero() {
				t.Fatal("DecidedAt not stamped")
			}

			// Reason verdicts carry reason.
			if tc.requireReason && report.Reason == "" {
				t.Fatal("reason empty for verdict that requires it")
			}

			// Verified carries proof.
			if tc.requireProof && len(report.Proof) == 0 {
				t.Fatal("proof empty for verdict that requires it")
			}

			// Reports marshal as JSON.
			b, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatalf("JSON: %v", marshalErr)
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(b, &m) != nil {
				t.Fatalf("report is not valid JSON: %s", b)
			}

			// Required keys.
			for _, k := range []string{"finding_id", "type", "verdict", "decided_at"} {
				if _, ok := m[k]; !ok {
					t.Errorf("missing key %q in report JSON", k)
				}
			}
		})
	}
}

// Redaction strips report and artifact secrets.
func TestRedactionAudit(t *testing.T) {
	const marker = "AUDIT_CANARY"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sensitive headers must redact.
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
    "base_request": {"method": "GET", "url": "http://app.example.com:` + portStr + `/download?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "` + marker + `", "repetitions": 2}
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

	// Check report JSON.
	reportJSON, _ := json.Marshal(report)
	assertNoSecrets(t, "report_json", string(reportJSON))

	// Check stored data.
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

// sensitivePatterns must never persist.
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
