// Package httpx replays through pinned IPs.
package httpx

import (
	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// RedirectHop is one checked hop.
type RedirectHop struct {
	From       string
	To         string
	StatusCode int
	Allowed    bool // policy verdict
}

// Capture records replay output.
type Capture struct {
	Request     evidence.Request
	StatusCode  int
	RespHeaders []evidence.Header
	RespBody    []byte
	DurationMS  int64 // monotonic, full lifecycle
	Redirects   []RedirectHop
}
