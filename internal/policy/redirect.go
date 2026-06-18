package policy

import "sync"

// redirectCounts tracks the number of redirect hops seen per Checker for the
// current chain. The PolicyEnforcer contract fixes CheckRedirect's signature to
// (from, to string) and the Checker struct shape is part of the package spine, so
// the per-chain hop counter cannot live on the Checker itself; it is keyed by the
// *Checker here instead. A job resets its count via ResetRedirects before driving
// a fresh request.
var redirectCounts sync.Map // map[*Checker]int

// ResetRedirects clears the redirect hop counter for this Checker, beginning a
// fresh chain. Callers (the httpx dialer / a worker) invoke this at the start of
// each top-level request so MaxRedirects bounds the hops of one chain, not the
// lifetime of the Checker.
func (c *Checker) ResetRedirects() {
	redirectCounts.Delete(c)
}

// nextRedirect increments and returns the hop count for this Checker's current
// chain.
func (c *Checker) nextRedirect() int {
	n := 1
	if v, ok := redirectCounts.Load(c); ok {
		n = v.(int) + 1
	}
	redirectCounts.Store(c, n)
	return n
}

// CheckRedirect re-runs the full URL policy on the redirect target. Every hop is
// re-canonicalized, re-scope-checked, and re-resolved + re-classified at
// PhaseRedirect, so a redirect cannot steer the verifier at a blocked IP, an
// out-of-scope host, or a non-http(s) scheme. The `from` URL is carried only for
// diagnostic context in the returned RejectionError.
//
// The hop count is bounded by Policy.MaxRedirects: each call counts as one hop of
// the current chain, and once the chain exceeds MaxRedirects the redirect is
// rejected with ReasonTooManyRedirect, so a redirect loop or an unbounded chain
// can never run forever. A non-positive MaxRedirects means "no per-hop bound
// enforced here" (the chain is still gated by AllowRedirects and the per-hop URL
// policy). Call ResetRedirects to begin a fresh chain.
//
// See specs/domains/policy/dns-ip-policy.md#redirect-handling.
func (c *Checker) CheckRedirect(from, to string) error {
	if !c.Policy.AllowRedirects {
		return reject(ReasonTooManyRedirect, to, nil)
	}
	if c.Policy.MaxRedirects > 0 {
		if hop := c.nextRedirect(); hop > c.Policy.MaxRedirects {
			return reject(ReasonTooManyRedirect, to, nil)
		}
	}
	if _, err := c.CheckURL(to, PhaseRedirect); err != nil {
		// CheckURL already returns a *RejectionError with the precise reason; on
		// rejection, surface it verbatim. On any other (defensive) error, wrap as
		// unparseable so the gate maps it to rejected rather than panicking.
		if _, ok := err.(*RejectionError); ok {
			return err
		}
		return reject(ReasonUnparseable, to, err)
	}
	return nil
}
