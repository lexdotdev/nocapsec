package engine

import (
	"context"
	"net"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// Security bypass attempts must reject.
func TestSecurityRegression_AllMustReject(t *testing.T) {
	cases := []struct {
		name    string
		finding string
		// resolver overrides public DNS.
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
    "base_request": {"method": "GET", "url": "https://app.example.com/x?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
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
    "base_request": {"method": "GET", "url": "https://app.example.com@evil.com/x?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
}`,
		},
		{
			// Confusable host normalizes out of scope.
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
    "base_request": {"method": "GET", "url": "https://ｅxample.com/x?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
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
    "base_request": {"method": "GET", "url": "http://169.254.169.254/latest/meta-data/?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
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
    "base_request": {"method": "GET", "url": "https://evil.com/admin?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
}`,
		},
		{
			// Blocked base_request still rejects.
			name: "internal/blocked address in base_request",
			finding: `{
  "finding_id": "sec-redir-internal",
  "type": "path_traversal.file_read",
  "target": {
    "expected_origin": "http://127.0.0.1",
    "allowed_hosts": ["127.0.0.1"],
    "allowed_schemes": ["http"]
  },
  "evidence": {
    "base_request": {"method": "GET", "url": "http://127.0.0.1/y?file=normal.txt"},
    "injection": {"location": {"kind": "query", "name": "file"}, "payloads": {"candidate": "../../etc/passwd", "control": "normal.txt"}}
  },
  "proof": {"expected_marker": "M", "repetitions": 2}
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
