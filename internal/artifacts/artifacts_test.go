package artifacts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

func TestSanitizeRedactsCookieHeader(t *testing.T) {
	input := "Cookie: session=abc123; user=admin\nContent-Type: text/html"
	got := string(Sanitize([]byte(input)))
	if strings.Contains(got, "abc123") {
		t.Fatal("cookie value not redacted")
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatal("redaction marker missing")
	}
	if !strings.Contains(got, "Content-Type: text/html") {
		t.Fatal("non-sensitive header damaged")
	}
}

func TestSanitizeRedactsAuthorizationHeader(t *testing.T) {
	input := "Authorization: Basic dXNlcjpwYXNz"
	got := string(Sanitize([]byte(input)))
	if strings.Contains(got, "dXNlcjpwYXNz") {
		t.Fatal("Authorization value not redacted")
	}
}

func TestSanitizeRedactsSetCookie(t *testing.T) {
	input := "Set-Cookie: token=secretval; Path=/; HttpOnly"
	got := string(Sanitize([]byte(input)))
	if strings.Contains(got, "secretval") {
		t.Fatal("Set-Cookie value not redacted")
	}
}

func TestSanitizeRedactsBearerToken(t *testing.T) {
	input := `{"auth": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"}`
	got := string(Sanitize([]byte(input)))
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatal("bearer token not redacted")
	}
}

func TestSanitizeRedactsCSRFToken(t *testing.T) {
	input := `csrf_token=abc123def456`
	got := string(Sanitize([]byte(input)))
	if strings.Contains(got, "abc123def456") {
		t.Fatal("CSRF token not redacted")
	}
}

func TestSanitizeRedactsPEMPrivateKey(t *testing.T) {
	input := "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretmaterial\n-----END RSA PRIVATE KEY-----\ndone"
	got := string(Sanitize([]byte(input)))
	if strings.Contains(got, "secretmaterial") || strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("PEM private key not redacted: %q", got)
	}
	if !strings.Contains(got, "done") {
		t.Fatal("surrounding content damaged")
	}
}

func TestSanitizeRedactsStandaloneJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	got := string(Sanitize([]byte(`{"token":"` + jwt + `"}`)))
	if strings.Contains(got, jwt) || strings.Contains(got, "eyJhbGci") {
		t.Fatalf("standalone JWT not redacted: %q", got)
	}
}

func TestSanitizeRedactsAWSAccessKey(t *testing.T) {
	got := string(Sanitize([]byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")))
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS access key not redacted: %q", got)
	}
}

func TestSanitizePreservesNonSensitive(t *testing.T) {
	input := "Content-Type: application/json\nX-Request-Id: 12345"
	got := string(Sanitize([]byte(input)))
	if got != input {
		t.Fatalf("non-sensitive content altered: %q", got)
	}
}

func TestSanitizeHeadersRedactsSensitive(t *testing.T) {
	headers := []evidence.Header{
		{Name: "Cookie", Value: "session=secret"},
		{Name: "Authorization", Value: "Bearer tok"},
		{Name: "Content-Type", Value: "text/html"},
		{Name: "Set-Cookie", Value: "id=val"},
	}
	got := SanitizeHeaders(headers)
	for _, h := range got {
		switch strings.ToLower(h.Name) {
		case "cookie", "authorization", "set-cookie":
			if h.Value != "[REDACTED]" {
				t.Errorf("%s value not redacted: %q", h.Name, h.Value)
			}
		case "content-type":
			if h.Value != "text/html" {
				t.Errorf("content-type altered: %q", h.Value)
			}
		}
	}
}

func TestStorePutGetRoundTrip(t *testing.T) {
	store := NewStore()
	ctx := context.Background()

	data := []byte("Content-Type: text/plain\nBody: hello world")
	ref, err := store.Put(ctx, "job-1", KindEvidence, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !strings.HasPrefix(ref, "artifact://job-1/evidence/") {
		t.Fatalf("ref format: %q", ref)
	}

	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, data)
	}
}

func TestStorePutSanitizesBeforeStorage(t *testing.T) {
	store := NewStore()
	ctx := context.Background()

	data := []byte("Cookie: session=supersecret\nBody: ok")
	ref, err := store.Put(ctx, "job-2", KindHTTPExchange, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if strings.Contains(string(got), "supersecret") {
		t.Fatal("credentials not sanitized before storage")
	}
}

func TestStoreGetNotFound(t *testing.T) {
	store := NewStore()
	_, err := store.Get(context.Background(), "artifact://missing/evidence/abc")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStoreRefIsStable(t *testing.T) {
	store := NewStore()
	ctx := context.Background()
	data := []byte("stable content")

	ref1, _ := store.Put(ctx, "j1", KindEvidence, data)
	ref2, _ := store.Put(ctx, "j1", KindEvidence, data)
	if ref1 != ref2 {
		t.Fatalf("refs differ for same content: %q vs %q", ref1, ref2)
	}
}
