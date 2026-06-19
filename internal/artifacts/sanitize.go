package artifacts

import (
	"regexp"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

const redacted = "[REDACTED]"

// sensitiveHeaders lists headers whose values are always redacted.
var sensitiveHeaders = map[string]bool{
	"cookie":              true,
	"authorization":       true,
	"set-cookie":          true,
	"proxy-authorization": true,
}

// bearerRe matches bearer-like tokens in arbitrary text.
var bearerRe = regexp.MustCompile(`(?i)\b[Bb]earer\s+[A-Za-z0-9\-._~+/]+=*`)

// headerValueRe matches Cookie/Authorization/Set-Cookie/CSRF header values
// in raw HTTP-like text (e.g. "Cookie: ...").
var headerValueRe = regexp.MustCompile(
	`(?im)^(Cookie|Set-Cookie|Authorization|Proxy-Authorization)\s*:\s*(.+)$`,
)

// csrfRe matches CSRF token patterns in form fields and JSON.
var csrfRe = regexp.MustCompile(
	`(?i)(csrf[-_]?token|_csrf|XSRF[-_]TOKEN|X-CSRF[-_]TOKEN)\s*[=:"]\s*[^\s"',;&]+`,
)

// pemRe matches PEM private-key blocks.
var pemRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

// jwtRe matches JWTs (three base64url segments).
var jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)

// awsKeyRe matches AWS access key IDs.
var awsKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b`)

// Sanitize redacts secrets from raw bytes before persistence.
func Sanitize(data []byte) []byte {
	s := string(data)
	s = headerValueRe.ReplaceAllString(s, "$1: "+redacted)
	s = pemRe.ReplaceAllLiteralString(s, redacted)
	s = bearerRe.ReplaceAllString(s, "Bearer "+redacted)
	s = jwtRe.ReplaceAllLiteralString(s, redacted)
	s = awsKeyRe.ReplaceAllLiteralString(s, redacted)
	s = csrfRe.ReplaceAllLiteralString(s, redacted)
	return []byte(s)
}

// SanitizeHeaders redacts values of sensitive headers in place.
func SanitizeHeaders(headers []evidence.Header) []evidence.Header {
	out := make([]evidence.Header, len(headers))
	for i, h := range headers {
		out[i] = h
		if sensitiveHeaders[strings.ToLower(strings.TrimSpace(h.Name))] {
			out[i].Value = redacted
		}
	}
	return out
}
