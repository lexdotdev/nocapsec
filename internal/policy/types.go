// Package policy is the standalone, mandatory security gate. Every URL and every
// outbound request — from the HTTP client, the browser proxy, and every worker —
// is checked here. Comparison is structural (canonicalized origins, label-anchored
// host matching), never string-based; DNS is resolved and pinned per request and
// every redirect hop is re-checked.
//
// This package imports only the standard library and golang.org/x/net/idna. It
// never imports execution packages. See specs/domains/policy/README.md,
// specs/contracts/policy-enforcer.md, and specs/decisions/006-strict-url-policy-package.md.
package policy

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// Phase distinguishes where a URL is being checked, so browser-phase checks can
// additionally consult the committed navigation.
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

// Reason codes for a rejection. They are stable and surfaced in reports.
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

// RejectionError is returned when a URL or redirect violates policy. The Reason
// is one of the stable Reason* codes; the gate maps it to the Rejected verdict.
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

// reject builds a RejectionError. Used throughout the package.
func reject(reason, raw string, err error) *RejectionError {
	return &RejectionError{Reason: reason, Raw: raw, Err: err}
}

// Origin is a normalized (scheme, host, port) triple. Ports are always explicit
// so equality is total.
type Origin struct {
	Scheme string
	Host   string
	Port   int
}

// Equal reports exact origin equality after normalization.
func (o Origin) Equal(other Origin) bool {
	return o.Scheme == other.Scheme && o.Host == other.Host && o.Port == other.Port
}

// String renders the origin as scheme://host:port.
func (o Origin) String() string {
	return fmt.Sprintf("%s://%s:%d", o.Scheme, o.Host, o.Port)
}

// URLPolicy is the per-target configuration that bounds what a finding may reach.
type URLPolicy struct {
	AllowedSchemes      []string
	AllowedHosts        []string
	AllowedHostSuffixes []string
	AllowedPorts        []int
	ExpectedOrigin      string

	AllowRedirects     bool
	MaxRedirects       int
	AllowExternalFinal bool
	ExternalFinalHosts []string

	BlockPrivateIPs    bool
	BlockLoopback      bool
	BlockLinkLocal     bool
	BlockMulticast     bool
	BlockUnspecified   bool
	BlockCloudMetadata bool
	ResolveCNAMEChain  bool

	// InternalAssessment, when true, permits otherwise-blocked ranges (the target
	// policy has explicitly opted into an internal assessment).
	InternalAssessment bool
}

// SafeURL is a URL that passed policy; it carries the pinned IP set the dialer
// must connect to.
type SafeURL struct {
	URL      *url.URL
	Origin   Origin
	PinnedIP []net.IP
}

// Resolver resolves a host to a set of IPs. It is injectable so tests do not hit
// the network. The default implementation wraps net.Resolver (see dns.go).
type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
}

// Checker enforces a URLPolicy. It is the concrete implementation behind the
// URL-checking half of the PolicyEnforcer contract. Method bodies live in
// url.go, origin.go, iprange.go, dns.go, and redirect.go.
type Checker struct {
	Policy   URLPolicy
	Resolver Resolver
}
