package policy

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile canonicalizes non-ASCII hosts like idna.Lookup, but disables the
// STD3 rule so underscores are tolerated consistently (e.g. srv_münchen). Label
// validation still runs, so malformed labels are still rejected.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

// NewChecker constructs a Checker for a policy and resolver.
func NewChecker(p URLPolicy, r Resolver) *Checker {
	return &Checker{Policy: p, Resolver: r}
}

// CheckURL runs the canonicalize + scope + DNS/IP pipeline and returns a SafeURL
// with the pinned IPs on success, else a *RejectionError with a stable reason.
// Order is fixed: cheap structural rejections run before any DNS resolution.
func (c *Checker) CheckURL(raw string, _ Phase) (*SafeURL, error) { //nolint:gocyclo // ordered security pipeline kept linear for auditability
	// 1. Trim, then reject any control/non-printable rune before it reaches
	// net/url's lenient parser (tabs, newlines, NUL, embedded controls).
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
		// Catches protocol-relative ("//evil.com") and scheme-less inputs.
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

	// 4. Reject userinfo (the URLPolicy shape never permits it).
	if u.User != nil {
		return nil, reject(ReasonUserinfo, raw, nil)
	}

	// 5. Host normalization.
	host := u.Hostname()
	if host == "" {
		return nil, reject(ReasonEmptyHost, raw, nil)
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".") // "example.com." -> "example.com"
	if host == "" {
		return nil, reject(ReasonEmptyHost, raw, nil)
	}
	// IDNA: convert unicode/confusable hosts to ASCII; pure-ASCII is left as-is.
	if !isASCII(host) {
		ascii, err := idnaProfile.ToASCII(host)
		if err != nil {
			return nil, reject(ReasonBadHost, raw, err)
		}
		host = strings.ToLower(ascii)
	}

	// Re-attach the normalized host (keeping any explicit port) so SafeURL.URL
	// is canonical.
	if p := u.Port(); p != "" {
		u.Host = host + ":" + p
	} else {
		u.Host = host
	}

	// 6. IP-literal host: classify directly, skip DNS. ParseHostIP normalizes
	// alternate encodings (decimal/octal/hex/short-form/mapped) to a canonical IP.
	if ip, isIP := ParseHostIP(host); isIP {
		canon := ip.String() // standard form so dialer and comparisons agree
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
		// An IP literal still satisfies host/port scope when the policy declares
		// allowed hosts; no host scope means range blocking only.
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

	// 8. Resolve and classify every IP; reject any in a blocked range (DNS
	// rebinding resistance). CheckURL has no ctx in its contract, so the
	// resolver drives its own timeout.
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

// schemeAllowed reports whether scheme is permitted; empty list means any.
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

// hasHostScope reports whether the policy declares any host allowance; none
// means host scope is not enforced.
func (c *Checker) hasHostScope() bool {
	return len(c.Policy.AllowedHosts) > 0 || len(c.Policy.AllowedHostSuffixes) > 0
}

// hostAllowed does structural, label-anchored matching (never substring/prefix).
// host must already be normalized (lower-case, no trailing dot, IDNA-ASCII).
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

// matchHostSuffix reports whether host is at or below suffix at a label
// boundary: ".example.com" matches "app.example.com" and the apex, but not
// "notexample.com" or "x.example.com.attacker.net".
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

// portAllowed reports whether port is permitted; empty list means any.
func (c *Checker) portAllowed(port int) bool {
	if len(c.Policy.AllowedPorts) == 0 {
		return true
	}
	return slices.Contains(c.Policy.AllowedPorts, port)
}

// isControlOrNonPrint reports whether r is a C0/C1 control rune.
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
