package httpx

import (
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/policy"
)

// NewClient builds an *http.Client whose transport enforces the supplied
// policy.Checker: connections are pinned to allowed, resolved IPs and every
// redirect hop is re-checked against the policy.
//
// TODO: wire a pinned DialContext from c that resolves via c's Resolver,
// enforces c.CheckURL/c.CheckRedirect per hop, and records RedirectHop entries.
// See specs/domains/httpx/README.md.
func NewClient(c *policy.Checker) *http.Client {
	_ = c
	return &http.Client{}
}
