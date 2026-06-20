// Package httpx replays requests via an
// IP-pinning transport (SSRF defense).
package httpx

import (
	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// RedirectHop is one step + its policy verdict.
type RedirectHop struct {
	From       string
	To         string
	StatusCode int
	Allowed    bool // policy verdict
}

// Capture holds a replay: response, timing,
// redirects.
type Capture struct {
	Request     evidence.Request
	StatusCode  int
	RespHeaders []evidence.Header
	RespBody    []byte
	DurationMS  int64 // monotonic, full lifecycle
	Redirects   []RedirectHop
}
