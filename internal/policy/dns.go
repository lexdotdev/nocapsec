package policy

import (
	"context"
	"net"
)

// systemResolver is the production Resolver, wrapping net.Resolver and
// returning the union of A/AAAA answers. The Go resolver follows CNAMEs
// transparently; explicit CNAME-chain inspection lands with the httpx dialer.
type systemResolver struct {
	r *net.Resolver
}

// NewSystemResolver returns the production Resolver. Tests inject a fake.
func NewSystemResolver() Resolver {
	return &systemResolver{r: net.DefaultResolver}
}

// Resolve looks up the host's IPs as canonical net.IP values.
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
