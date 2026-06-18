package httpx

import (
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/policy"
)

// NewClient builds an *http.Client whose transport enforces c: connections are
// pinned to resolved, allowed IPs and every redirect hop is re-checked.
//
// TODO: wire a pinned DialContext that resolves via c's Resolver, enforces
// CheckURL/CheckRedirect per hop, and records RedirectHop entries.
func NewClient(c *policy.Checker) *http.Client {
	_ = c
	return &http.Client{}
}
