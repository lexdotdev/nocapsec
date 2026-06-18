package policy

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile is the IDNA profile used to canonicalize non-ASCII hosts. It
// mirrors idna.Lookup (security mapping for lookup, BidiRule, non-transitional)
// but disables the STD3 hostname rule (StrictDomainName(false)) so underscores
// are tolerated — matching the documented intent that pure-ASCII hosts skip IDNA
// "which would otherwise reject e.g. underscores aggressively". Without this, a
// host that mixes an underscore label with any unicode label (e.g.
// "srv_münchen.example.com") was inconsistently rejected with ReasonBadHost while
// the all-ASCII equivalent was accepted. Label validation (CheckHyphens,
// ValidateLabels) still runs, so genuinely malformed labels are still rejected.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

// NewChecker constructs a Checker for a given policy and resolver. The resolver
// is injectable so tests do not touch the network; production wires
// NewSystemResolver (see dns.go).
func NewChecker(p URLPolicy, r Resolver) *Checker {
	return &Checker{Policy: p, Resolver: r}
}

// CheckURL runs the full canonicalization + scope + DNS/IP pipeline on a raw URL
// and returns a SafeURL carrying the pinned IP set on success. Every failure is a
// *RejectionError with a stable Reason* code. The pipeline order matches
// specs/domains/policy/url-canonicalizer.md and is intentionally fixed: cheap
// structural rejections happen before any DNS resolution.
func (c *Checker) CheckURL(raw string, phase Phase) (*SafeURL, error) {
	// 1. Trim surrounding whitespace; reject any remaining control / non-printable
	// rune. Tabs, newlines, NUL, and embedded controls are all rejected here so
	// they can never reach net/url's lenient parser.
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, reject(ReasonUnparseable, raw, nil)
	}
	if i := strings.IndexFunc(trimmed, isControlOrNonPrint); i >= 0 {
		return nil, reject(ReasonControlChar, raw, nil)
	}

	// 2. Parse with net/url. Require an absolute URL with a host.
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, reject(ReasonUnparseable, raw, err)
	}
	if !u.IsAbs() {
		// Catches protocol-relative ("//evil.com/path") and scheme-less inputs.
		return nil, reject(ReasonBadScheme, raw, nil)
	}

	// 3. Lower-case scheme; require http/https.
	scheme := strings.ToLower(u.Scheme)
	u.Scheme = scheme
	if scheme != "http" && scheme != "https" {
		return nil, reject(ReasonBadScheme, raw, nil)
	}
	if !c.schemeAllowed(scheme) {
		return nil, reject(ReasonBadScheme, raw, nil)
	}

	// 4. Reject userinfo unless the policy explicitly allows it (it never does in
	// the current URLPolicy shape, so always reject).
	if u.User != nil {
		return nil, reject(ReasonUserinfo, raw, nil)
	}

	// 5. Host normalization.
	host := u.Hostname()
	if host == "" {
		return nil, reject(ReasonEmptyHost, raw, nil)
	}
	host = strings.ToLower(host)
	// Strip a single trailing dot ("example.com." -> "example.com").
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, reject(ReasonEmptyHost, raw, nil)
	}
	// IDNA: convert unicode/confusable hosts to ASCII. Pure-ASCII hosts are left
	// untouched (idna would otherwise reject e.g. underscores aggressively). The
	// profile used here (idnaProfile) also tolerates underscores in non-ASCII
	// hosts, so the treatment of underscores is consistent regardless of whether a
	// sibling label happens to be unicode.
	if !isASCII(host) {
		ascii, err := idnaProfile.ToASCII(host)
		if err != nil {
			return nil, reject(ReasonBadHost, raw, err)
		}
		host = strings.ToLower(ascii)
	}

	// Re-attach the normalized host (preserving any explicit port) so the
	// returned SafeURL.URL is canonical and Origin construction is consistent.
	if p := u.Port(); p != "" {
		u.Host = host + ":" + p
	} else {
		u.Host = host
	}

	// 6. If the host is an IP literal, classify it directly and skip DNS. This is
	// where alternate encodings (decimal/octal/hex/short-form/IPv4-mapped) are
	// normalized to a canonical net.IP before range classification.
	if ip, isIP := ParseHostIP(host); isIP {
		// Canonicalize the host text to the standard form so downstream
		// comparisons and the dialer agree.
		canon := ip.String()
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

		if blocked, _ := c.ipBlockedByPolicy(ip); blocked {
			return nil, reject(ReasonBlockedIP, raw, nil)
		}

		origin, ok := OriginFromURL(u)
		if !ok {
			return nil, reject(ReasonBadPort, raw, nil)
		}
		// Even an IP literal must satisfy host/port scope when the policy declares
		// allowed hosts. An empty AllowedHosts+suffix set means "no host scope"
		// (used by the IP-policy tests that only care about range blocking).
		if !c.portAllowed(origin.Port) {
			return nil, reject(ReasonBadPort, raw, nil)
		}
		if c.hasHostScope() && !c.hostAllowed(canon) {
			return nil, reject(ReasonOutOfScopeHost, raw, nil)
		}
		return &SafeURL{URL: u, Origin: origin, PinnedIP: []net.IP{ip}}, nil
	}

	// 7. Build Origin and check host + port scope.
	origin, ok := OriginFromURL(u)
	if !ok {
		return nil, reject(ReasonBadPort, raw, nil)
	}
	if c.hasHostScope() {
		if !c.hostAllowed(host) {
			return nil, reject(ReasonOutOfScopeHost, raw, nil)
		}
	}
	if !c.portAllowed(origin.Port) {
		return nil, reject(ReasonBadPort, raw, nil)
	}

	// 8. Resolve via the injected resolver and classify every IP. Reject if any
	// resolved IP is in a blocked range (DNS rebinding / pinning resistance).
	if c.Resolver == nil {
		return nil, reject(ReasonUnresolvable, raw, nil)
	}
	ips, err := c.Resolver.Resolve(ctxBackground(), host)
	if err != nil {
		return nil, reject(ReasonUnresolvable, raw, err)
	}
	if len(ips) == 0 {
		return nil, reject(ReasonUnresolvable, raw, nil)
	}
	pinned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if blocked, _ := c.ipBlockedByPolicy(ip); blocked {
			return nil, reject(ReasonBlockedIP, raw, nil)
		}
		pinned = append(pinned, ip)
	}

	return &SafeURL{URL: u, Origin: origin, PinnedIP: pinned}, nil
}

// schemeAllowed reports whether scheme is permitted by the policy. An empty
// AllowedSchemes list means "use the http/https default" (already enforced
// above), so it returns true.
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

// hasHostScope reports whether the policy declares any host allowance. When it
// declares none, host scope is not enforced (the IP-range tests rely on this).
func (c *Checker) hasHostScope() bool {
	return len(c.Policy.AllowedHosts) > 0 || len(c.Policy.AllowedHostSuffixes) > 0
}

// hostAllowed performs structural, label-anchored host matching. It never uses
// substring/prefix comparison. host must already be normalized (lower-cased,
// trailing-dot stripped, IDNA-ASCII).
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

// matchHostSuffix reports whether host is at or below the suffix at a DNS-label
// boundary. The suffix is normalized to begin with a single dot, so
// ".example.com" matches "app.example.com" but not "notexample.com" and not
// "x.example.com.attacker.net".
func matchHostSuffix(host, suffix string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	if suffix == "" {
		return false
	}
	if !strings.HasPrefix(suffix, ".") {
		suffix = "." + suffix
	}
	// The bare apex ("example.com" for suffix ".example.com") is also a match.
	apex := strings.TrimPrefix(suffix, ".")
	if host == apex {
		return true
	}
	// Label-anchored: host must end with the dotted suffix.
	return strings.HasSuffix(host, suffix)
}

// portAllowed reports whether port is permitted. An empty AllowedPorts list
// means "any port the scheme produced is fine".
func (c *Checker) portAllowed(port int) bool {
	if len(c.Policy.AllowedPorts) == 0 {
		return true
	}
	for _, p := range c.Policy.AllowedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// isControlOrNonPrint reports whether r is a C0/C1 control or other
// non-printable rune that must never appear in a URL we accept.
func isControlOrNonPrint(r rune) bool {
	if r < 0x20 || r == 0x7f {
		return true
	}
	if r >= 0x80 && r <= 0x9f {
		return true
	}
	return false
}

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
