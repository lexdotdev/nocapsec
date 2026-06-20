package policy

import (
	"context"
	"net"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile canonicalizes non-ASCII hosts;
// STD3 off (underscores), labels still validated.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

// NewChecker constructs a Checker.
func NewChecker(p URLPolicy, r Resolver) *Checker {
	return &Checker{Policy: p, Resolver: r}
}

// CheckURL: canonicalize + scope + DNS/IP ->
// SafeURL with pinned IPs;
// structural rejections before DNS.
func (c *Checker) CheckURL(raw string, _ Phase) (*SafeURL, error) { //nolint:gocyclo // ordered security pipeline kept linear for auditability
	// 1. Reject control runes before
	// net/url's lenient parser.
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, reject(ReasonUnparseable, raw, nil)
	}
	if i := strings.IndexFunc(trimmed, isControlOrNonPrint); i >= 0 {
		return nil, reject(ReasonControlChar, raw, nil)
	}

	// 2. Parse; require an absolute URL with a host.
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, reject(ReasonUnparseable, raw, err)
	}
	if !u.IsAbs() {
		// Catches protocol-relative ("//evil.com")
		// and scheme-less.
		return nil, reject(ReasonBadScheme, raw, nil)
	}

	// 3. Lower-case scheme; require http/https.
	scheme := strings.ToLower(u.Scheme)
	u.Scheme = scheme
	if scheme != schemeHTTP && scheme != schemeHTTPS {
		return nil, reject(ReasonBadScheme, raw, nil)
	}
	if !c.schemeAllowed(scheme) {
		return nil, reject(ReasonBadScheme, raw, nil)
	}

	// 4. Reject userinfo; never permitted.
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
	// IDNA: convert unicode/confusable hosts to ASCII.
	if !isASCII(host) {
		ascii, err := idnaProfile.ToASCII(host)
		if err != nil {
			return nil, reject(ReasonBadHost, raw, err)
		}
		host = strings.ToLower(ascii)
	}

	// Re-attach normalized host (with port) so
	// SafeURL.URL is canonical.
	if p := u.Port(); p != "" {
		u.Host = host + ":" + p
	} else {
		u.Host = host
	}

	// 6. IP-literal host: normalize alt encodings,
	// classify, skip DNS.
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
		// IP literals honor host/port scope;
		// no host scope = range block only.
		if !c.portAllowed(origin.Port) {
			return nil, reject(ReasonBadPort, raw, nil)
		}
		if c.hasHostScope() && !c.hostAllowed(canon) {
			return nil, reject(ReasonOutOfScopeHost, raw, nil)
		}
		return &SafeURL{URL: u, Origin: origin, PinnedIP: []net.IP{ip}}, nil
	}

	// 7. Build Origin; check host + port scope.
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

	// 8. Resolve + classify every IP; reject blocked
	// range (DNS rebinding resistance).
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

// schemeAllowed reports scheme allowed; empty=any.
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

// hasHostScope reports if any host allowance set.
func (c *Checker) hasHostScope() bool {
	return len(c.Policy.AllowedHosts) > 0 || len(c.Policy.AllowedHostSuffixes) > 0
}

// hostAllowed: label-anchored match
// (never substring); host normalized.
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

// matchHostSuffix matches on a label boundary,
// not "notexample.com".
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

// portAllowed reports if port allowed; empty = any.
func (c *Checker) portAllowed(port int) bool {
	if len(c.Policy.AllowedPorts) == 0 {
		return true
	}
	return slices.Contains(c.Policy.AllowedPorts, port)
}

// isControlOrNonPrint reports a C0/C1 control rune.
func isControlOrNonPrint(r rune) bool {
	if r < 0x20 || r == 0x7f {
		return true
	}
	if r >= 0x80 && r <= 0x9f {
		return true
	}
	return false
}

// isASCII reports if s is all ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
