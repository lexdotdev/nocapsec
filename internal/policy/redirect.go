package policy

import "errors"

// ResetRedirects begins a fresh redirect chain. Call before each top-level
// request so MaxRedirects bounds one chain, not the Checker's lifetime.
func (c *Checker) ResetRedirects() { c.redirects = 0 }

// CheckRedirect re-runs the full URL policy on each redirect hop and bounds the
// chain by MaxRedirects, so a redirect cannot steer to a blocked IP, an
// out-of-scope host, or a non-http(s) scheme — and a loop cannot run forever.
func (c *Checker) CheckRedirect(_, to string) error {
	if !c.Policy.AllowRedirects {
		return reject(ReasonTooManyRedirect, to, nil)
	}
	if c.Policy.MaxRedirects > 0 {
		c.redirects++
		if c.redirects > c.Policy.MaxRedirects {
			return reject(ReasonTooManyRedirect, to, nil)
		}
	}
	if _, err := c.CheckURL(to, PhaseRedirect); err != nil {
		// CheckURL returns a precise *RejectionError; surface it verbatim. Wrap
		// any other (defensive) error so the gate rejects rather than panics.
		var re *RejectionError
		if errors.As(err, &re) {
			return err
		}
		return reject(ReasonUnparseable, to, err)
	}
	return nil
}
