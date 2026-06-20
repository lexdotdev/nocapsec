// Package policy is the mandatory security gate
// for every outbound URL.
package policy

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// Phase is where a URL check happens.
type Phase int

const (
	PhaseInitial Phase = iota
	PhaseRedirect
	PhaseBrowserNav
)

func (p Phase) String() string {
	switch p {
	case PhaseInitial:
		return "initial"
	case PhaseRedirect:
		return "redirect"
	case PhaseBrowserNav:
		return "browser_nav"
	default:
		return "unknown"
	}
}

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// Stable rejection reason codes, used in reports.
const (
	ReasonControlChar     = "control_char"
	ReasonUnparseable     = "unparseable"
	ReasonBadScheme       = "bad_scheme"
	ReasonUserinfo        = "userinfo"
	ReasonEmptyHost       = "empty_host"
	ReasonOutOfScopeHost  = "out_of_scope_host"
	ReasonBadPort         = "bad_port"
	ReasonBadHost         = "bad_host"
	ReasonBlockedIP       = "blocked_ip"
	ReasonUnresolvable    = "unresolvable"
	ReasonTooManyRedirect = "too_many_redirects"
)

// RejectionError reports a violation;
// Reason is a stable code.
type RejectionError struct {
	Reason string
	Raw    string
	Err    error
}

func (e *RejectionError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("policy: %s (%q): %v", e.Reason, e.Raw, e.Err)
	}
	return fmt.Sprintf("policy: %s (%q)", e.Reason, e.Raw)
}

func (e *RejectionError) Unwrap() error { return e.Err }

func reject(reason, raw string, err error) *RejectionError {
	return &RejectionError{Reason: reason, Raw: raw, Err: err}
}

// Origin is a normalized scheme/host/port;
// port always explicit.
type Origin struct {
	Scheme string
	Host   string
	Port   int
}

// Equal reports origin equality after normalizing.
func (o Origin) Equal(other Origin) bool {
	return o.Scheme == other.Scheme && o.Host == other.Host && o.Port == other.Port
}

func (o Origin) String() string {
	return fmt.Sprintf("%s://%s:%d", o.Scheme, o.Host, o.Port)
}

// URLPolicy bounds what a finding may reach.
type URLPolicy struct {
	AllowedSchemes      []string
	AllowedHosts        []string
	AllowedHostSuffixes []string
	AllowedPorts        []int
	ExpectedOrigin      string

	AllowRedirects bool
	MaxRedirects   int

	BlockPrivateIPs    bool
	BlockLoopback      bool
	BlockLinkLocal     bool
	BlockMulticast     bool
	BlockUnspecified   bool
	BlockCloudMetadata bool

	// InternalAssessment opts into blocked ranges.
	InternalAssessment bool
}

// SafeURL passed policy; carries pinned IPs
// for the dialer.
type SafeURL struct {
	URL      *url.URL
	Origin   Origin
	PinnedIP []net.IP
}

// Resolver maps a host to IPs; injected in tests.
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
}

// Checker enforces a URLPolicy.
type Checker struct {
	Policy   URLPolicy
	Resolver Resolver

	// redirects counts hops in the current chain.
	redirects int
}
