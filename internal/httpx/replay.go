package httpx

import (
	"context"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// Replay executes a recorded request verbatim using the supplied client and
// captures the request and response bytes, status, redirect trace, and
// monotonic latency.
//
// TODO: build the *http.Request from req, time the full lifecycle with a
// monotonic clock, and populate Capture (incl. Redirects via the client's
// transport). See specs/domains/httpx/README.md.
func Replay(ctx context.Context, client *http.Client, req evidence.Request) (*Capture, error) {
	_ = ctx
	_ = client
	_ = req
	return nil, ErrNotImplemented
}
