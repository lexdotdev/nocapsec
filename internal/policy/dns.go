package policy

import (
	"context"
	"net"
)

// systemResolver is the default Resolver used in production. It wraps the
// standard net.Resolver and returns the union of A/AAAA answers. CNAME-chain
// walking (when ResolveCNAMEChain is set) is handled by the higher-level dialer;
// the Go resolver already follows CNAMEs transparently for LookupIPAddr.
//
// TODO(specs/domains/policy/dns-ip-policy.md): expose explicit CNAME-chain
// inspection and per-job answer caching once the httpx dialer is wired.
type systemResolver struct {
	r *net.Resolver
}

// NewSystemResolver returns the production Resolver backed by net.Resolver. It is
// used to construct a Checker in production and is deliberately NOT used in
// tests, which inject a fake Resolver so they never touch the network.
func NewSystemResolver() Resolver {
	return &systemResolver{r: net.DefaultResolver}
}

// Resolve looks up the host's IP addresses, returning canonical net.IP values.
func (s *systemResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := s.r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// ctxBackground centralizes the context used for the internal resolve call in
// CheckURL, which has no ctx parameter in its contract signature. Callers that
// need cancellation should drive timeouts through the resolver implementation.
func ctxBackground() context.Context { return context.Background() }
