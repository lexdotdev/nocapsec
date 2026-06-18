package httpx

import (
	"context"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// Replay executes req verbatim with client and captures the request/response
// bytes, status, redirect trace, and monotonic latency.
//
// TODO: build the *http.Request from req, time the full lifecycle, and populate
// Capture (incl. Redirects via the transport).
func Replay(ctx context.Context, client *http.Client, req evidence.Request) (*Capture, error) {
	_ = ctx
	_ = client
	_ = req
	return nil, ErrNotImplemented
}
