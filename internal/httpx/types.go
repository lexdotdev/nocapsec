// Package httpx replays the exact requests a finding supplies. It uses a custom
// transport that enforces DNS pinning and origin policy, captures request and
// response bytes, traces redirects hop-by-hop, and measures latency with a
// monotonic clock. It is the execution substrate for all server-side
// validators.
//
// See specs/domains/httpx/README.md.
package httpx

import (
	"errors"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// ErrNotImplemented is returned by stubbed functions that are not yet wired up.
var ErrNotImplemented = errors.New("httpx: not implemented")

// RedirectHop records a single redirect step and the policy verdict for it.
type RedirectHop struct {
	From       string
	To         string
	StatusCode int
	Allowed    bool // policy verdict for this hop
}

// Capture holds the replayed request together with the captured response,
// timing, and per-hop redirect trace.
type Capture struct {
	Request     evidence.Request
	StatusCode  int
	RespHeaders []evidence.Header
	RespBody    []byte
	DurationMS  int64 // monotonic, full request lifecycle
	Redirects   []RedirectHop
}
