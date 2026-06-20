package policy

import (
	"context"
	"net"
)

// systemResolver wraps net.Resolver; A/AAAA only.
type systemResolver struct {
	r *net.Resolver
}

// NewSystemResolver returns the prod Resolver.
func NewSystemResolver() Resolver {
	return &systemResolver{r: net.DefaultResolver}
}

// Resolve looks up the host's IPs.
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
