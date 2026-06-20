package httpx

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/policy"
)

// maxResponseBytes caps the response body (4 MiB).
const maxResponseBytes = 4 << 20

// Replay runs req through the policy-pinned
// client (SSRF defense).
func Replay(ctx context.Context, b *ClientBundle, req evidence.Request) (*Capture, error) {
	// Pin IPs for the initial URL (SSRF defense).
	b.Checker.ResetRedirects()
	safe, err := b.Checker.CheckURL(req.URL, policy.PhaseInitial) //nolint:contextcheck // CheckURL's contract drives its own resolver timeout
	if err != nil {
		return nil, fmt.Errorf("httpx: initial URL rejected: %w", err)
	}
	b.Pinned.Set(safe.PinnedIP)
	b.Tracker.Reset()

	httpReq, err := buildRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("httpx: build request: %w", err)
	}

	start := time.Now() // monotonic
	resp, err := b.Client.Do(httpReq)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("httpx: do: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("httpx: read body: %w", err)
	}

	respHeaders := make([]evidence.Header, 0, len(resp.Header))
	for name, vals := range resp.Header {
		for _, v := range vals {
			respHeaders = append(respHeaders, evidence.Header{Name: name, Value: v})
		}
	}

	return &Capture{
		Request:     req,
		StatusCode:  resp.StatusCode,
		RespHeaders: respHeaders,
		RespBody:    body,
		DurationMS:  elapsed.Milliseconds(),
		Redirects:   b.Tracker.Snapshot(),
	}, nil
}

// buildRequest builds a request from evidence.
func buildRequest(ctx context.Context, req evidence.Request) (*http.Request, error) {
	var body io.Reader = http.NoBody
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}

	for _, h := range req.Headers {
		httpReq.Header.Add(h.Name, h.Value)
	}

	return httpReq, nil
}
