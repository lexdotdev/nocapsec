package engine

import (
	"context"
	"net"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// TestSecurityRegression_AllMustReject is the table-driven security regression
// suite. Each case constructs a malicious finding that MUST map to Rejected.
// If any case returns Verified, NotReproduced, or Inconclusive, the security
// model has a hole.
func TestSecurityRegression_AllMustReject(t *testing.T) {
	cases := []struct {
		name    string
		finding string
		// resolver overrides the default public resolver.
		resolver func() fakeResolver
	}{
		{
			name: "DNS rebinding: in-scope host resolves to private IP",
			finding: `{
  "finding_id": "sec-dns-rebind",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
			resolver: func() fakeResolver {
				return fakeResolver{ips: []net.IP{net.ParseIP("10.0.0.1")}}
			},
		},
		{
			name: "userinfo bypass: example.com@evil.com",
			finding: `{
  "finding_id": "sec-userinfo",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com@evil.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
		},
		{
			// Fullwidth 'ａ' (U+FF41) in "app" becomes "app" after IDNA mapping,
			// so the host normalizes to "app.example.com". However the evidence
			// URL uses "ａpp.example.com" which, after normalization, matches the
			// allowed host. The real bypass attempt is a confusable that normalizes
			// to a DIFFERENT host: "ｅxample.com" -> "example.com", which is NOT
			// "app.example.com".
			name: "punycode/IDNA confusable bypass",
			finding: `{
  "finding_id": "sec-punycode",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://ｅxample.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
		},
		{
			name: "cloud-metadata IP (169.254.169.254)",
			finding: `{
  "finding_id": "sec-cloud-meta",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://169.254.169.254",
    "allowed_hosts": ["169.254.169.254"],
    "allowed_schemes": ["http"]
  },
  "evidence": {
    "request": {"method": "GET", "url": "http://169.254.169.254/latest/meta-data/"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "http://169.254.169.254/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
		},
		{
			name: "open-relay attempt: evidence URL to out-of-scope host",
			finding: `{
  "finding_id": "sec-open-relay",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://evil.com/admin"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "https://app.example.com/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
		},
		{
			name: "redirect to internal/blocked address via control URL",
			finding: `{
  "finding_id": "sec-redir-internal",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "https://app.example.com",
    "allowed_hosts": ["app.example.com"],
    "allowed_schemes": ["https"]
  },
  "evidence": {
    "request": {"method": "GET", "url": "https://app.example.com/x"},
    "vulnerable_parameter": "file",
    "expected_markers": ["M"],
    "negative_control": {"method": "GET", "url": "http://127.0.0.1/y"}
  },
  "proof": {"require_marker": true, "require_negative_control_absent": true}
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := publicResolver()
			if tc.resolver != nil {
				resolver = tc.resolver()
			}

			e, err := New(Config{Resolver: resolver})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer func() { _ = e.Close() }()

			report, err := e.Verify(context.Background(), []byte(tc.finding))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if report.Verdict != verdict.Rejected {
				t.Fatalf("verdict = %q (reason=%q), want rejected", report.Verdict, report.Reason)
			}
		})
	}
}
