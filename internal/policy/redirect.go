package policy

import "errors"

// ResetRedirects starts a fresh chain so
// MaxRedirects bounds one req.
func (c *Checker) ResetRedirects() { c.redirects = 0 }

// CheckRedirect: per-hop re-check + chain cap;
// no redirect to a blocked target.
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
		// Surface RejectionError verbatim; wrap
		// else so the gate rejects.
		var re *RejectionError
		if errors.As(err, &re) {
			return err
		}
		return reject(ReasonUnparseable, to, err)
	}
	return nil
}
