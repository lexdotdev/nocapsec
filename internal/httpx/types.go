// Package httpx replays a finding's exact requests through a transport that
// pins DNS and enforces origin policy, capturing request/response bytes, a
// hop-by-hop redirect trace, and monotonic latency. It is the execution
// substrate for server-side validators.
package httpx

import (
	"github.com/lexdotdev/nocapsec/internal/evidence"
)

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
