package policy

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// IDNA with underscores allowed.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

// NewChecker builds a Checker.
func NewChecker(p URLPolicy, r Resolver) *Checker {
	return &Checker{Policy: p, Resolver: r}
}

// CheckURL returns a policy-pinned URL.
func (c *Checker) CheckURL(raw string, phase Phase) (*SafeURL, error) { //nolint:gocyclo // audit path
	// Reject before net/url leniency.
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, reject(ReasonUnparseable, raw, nil)
	}
	if i := strings.IndexFunc(trimmed, isControlOrNonPrint); i >= 0 {
		return nil, reject(ReasonControlChar, raw, nil)
	}

	// Require an absolute URL with a host.
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, reject(ReasonUnparseable, raw, err)
	}
	if !u.IsAbs() {
		return nil, reject(ReasonBadScheme, raw, nil)
	}

	scheme := strings.ToLower(u.Scheme)
	u.Scheme = scheme
	if scheme != schemeHTTP && scheme != schemeHTTPS {
		return nil, reject(ReasonBadScheme, raw, nil)
	}
	if !c.schemeAllowed(scheme) {
		return nil, reject(ReasonBadScheme, raw, nil)
	}

	// Userinfo tricks host checks.
	if u.User != nil {
		return nil, reject(ReasonUserinfo, raw, nil)
	}

	host := u.Hostname()
	if host == "" {
		return nil, reject(ReasonEmptyHost, raw, nil)
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".") // "example.com." -> "example.com"
	if host == "" {
		return nil, reject(ReasonEmptyHost, raw, nil)
	}
	// IDNA maps confusables to ASCII.
	if !isASCII(host) {
		ascii, err := idnaProfile.ToASCII(host)
		if err != nil {
			return nil, reject(ReasonBadHost, raw, err)
		}
		host = strings.ToLower(ascii)
	}

	// Reattach normalized host.
	if p := u.Port(); p != "" {
		u.Host = host + ":" + p
	} else {
		u.Host = host
	}

	// IP literals skip DNS.
	if ip, isIP := ParseHostIP(host); isIP {
		canon := ip.String() // standard form for dialer/comparisons
		if p := u.Port(); p != "" {
			if ip.To4() == nil {
				u.Host = "[" + canon + "]:" + p
			} else {
				u.Host = canon + ":" + p
			}
		} else if ip.To4() == nil {
			u.Host = "[" + canon + "]"
		} else {
			u.Host = canon
		}

		if c.ipBlockedByPolicy(ip) {
			return nil, reject(ReasonBlockedIP, raw, nil)
		}

		origin, ok := OriginFromURL(u)
		if !ok {
			return nil, reject(ReasonBadPort, raw, nil)
		}
		if !c.externalFinalAllowed(origin, phase) {
			// No host scope = range block only.
			if !c.portAllowed(origin.Port) {
				return nil, reject(ReasonBadPort, raw, nil)
			}
			if c.hasHostScope() && !c.hostAllowed(canon) {
				return nil, reject(ReasonOutOfScopeHost, raw, nil)
			}
		}
		return &SafeURL{URL: u, Origin: origin, PinnedIP: []net.IP{ip}}, nil
	}

	// Check host and port scope.
	origin, ok := OriginFromURL(u)
	if !ok {
		return nil, reject(ReasonBadPort, raw, nil)
	}
	external := c.externalFinalAllowed(origin, phase)
	if !external && c.hasHostScope() {
		if !c.hostAllowed(host) {
			return nil, reject(ReasonOutOfScopeHost, raw, nil)
		}
	}
	if !external && !c.portAllowed(origin.Port) {
		return nil, reject(ReasonBadPort, raw, nil)
	}

	// Pin and classify every resolved IP.
	if c.Resolver == nil {
		return nil, reject(ReasonUnresolvable, raw, nil)
	}
	ips, err := c.Resolver.Resolve(context.Background(), host)
	if err != nil {
		return nil, reject(ReasonUnresolvable, raw, err)
	}
	if len(ips) == 0 {
		return nil, reject(ReasonUnresolvable, raw, nil)
	}
	pinned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if c.ipBlockedByPolicy(ip) {
			return nil, reject(ReasonBlockedIP, raw, nil)
		}
		pinned = append(pinned, ip)
	}

	return &SafeURL{URL: u, Origin: origin, PinnedIP: pinned}, nil
}

// Empty scheme allowlist means any.
func (c *Checker) schemeAllowed(scheme string) bool {
	if len(c.Policy.AllowedSchemes) == 0 {
		return true
	}
	for _, s := range c.Policy.AllowedSchemes {
		if strings.EqualFold(s, scheme) {
			return true
		}
	}
	return false
}

func (c *Checker) externalFinalAllowed(origin Origin, phase Phase) bool {
	if !c.Policy.AllowExternalFinal || phase == PhaseInitial {
		return false
	}
	for _, allowed := range c.Policy.ExternalFinalOrigins {
		if origin.Equal(allowed) {
			return true
		}
	}
	return false
}

// hasHostScope reports host bounds.
func (c *Checker) hasHostScope() bool {
	return len(c.Policy.AllowedHosts) > 0 || len(c.Policy.AllowedHostSuffixes) > 0
}

// hostAllowed is label-anchored.
func (c *Checker) hostAllowed(host string) bool {
	for _, h := range c.Policy.AllowedHosts {
		if strings.EqualFold(strings.TrimSuffix(h, "."), host) {
			return true
		}
	}
	for _, suf := range c.Policy.AllowedHostSuffixes {
		if matchHostSuffix(host, suf) {
			return true
		}
	}
	return false
}

// matchHostSuffix rejects substrings.
func matchHostSuffix(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	if suffix == "" {
		return false
	}
	if !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}
	if host == strings.TrimPrefix(suffix, ".") { // bare apex
		return true
	}
	return strings.HasSuffix(host, suffix)
}

// Empty port allowlist means any.
func (c *Checker) portAllowed(port int) bool {
	if len(c.Policy.AllowedPorts) == 0 {
		return true
	}
	return slices.Contains(c.Policy.AllowedPorts, port)
}

// isControlOrNonPrint rejects C0/C1.
func isControlOrNonPrint(r rune) bool {
	if r < 0x20 || r == 0x7f {
		return true
	}
	if r >= 0x80 && r <= 0x9f {
		return true
	}
	return false
}

// isASCII reports byte-level ASCII.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
