package policy

import (
	"context"
	"errors"
	"net"
	"testing"
)

// fakeResolver returns a fixed IP set regardless of host, so positive-path tests
// never touch the network. The default IP is a public address (example.com's
// historical A record), which must NOT be blocked by ClassifyIP.
type fakeResolver struct {
	ips []net.IP
	err error
}

func (f fakeResolver) Resolve(_ context.Context, _ string) ([]net.IP, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ips, nil
}

// publicResolver resolves everything to a known public IP.
func publicResolver() Resolver {
	return fakeResolver{ips: []net.IP{net.ParseIP("93.184.216.34")}}
}

// scopePolicy is the canonical scope used by the canonicalizer tests:
// https only, host app.example.com, port 443.
func scopePolicy() URLPolicy {
	return URLPolicy{
		AllowedSchemes:   []string{"http", "https"},
		AllowedHosts:     []string{"app.example.com"},
		AllowedPorts:     []int{443},
		BlockLoopback:    true,
		BlockPrivateIPs:  true,
		BlockLinkLocal:   true,
		BlockMulticast:   true,
		BlockUnspecified: true,
	}
}

// ipPolicy allows http/https and any host, but relies on ClassifyIP to block
// internal ranges. Used by the IP-literal cases.
func ipPolicy() URLPolicy {
	return URLPolicy{
		AllowedSchemes:     []string{"http", "https"},
		AllowedPorts:       []int{80, 443},
		BlockLoopback:      true,
		BlockPrivateIPs:    true,
		BlockLinkLocal:     true,
		BlockMulticast:     true,
		BlockUnspecified:   true,
		BlockCloudMetadata: true,
	}
}

// assertReject checks that err is a *RejectionError and, when wantReason is
// non-empty, that the reason matches.
func assertReject(t *testing.T, err error, wantReason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rejection, got nil error")
	}
	var re *RejectionError
	if !errors.As(err, &re) {
		t.Fatalf("expected *RejectionError, got %T: %v", err, err)
	}
	if wantReason != "" && re.Reason != wantReason {
		t.Fatalf("reason = %q, want %q (err: %v)", re.Reason, wantReason, err)
	}
}

// --- Nasty-URL regression contract (canonicalizer scope) ---------------------

func TestCheckURL_NastyScope(t *testing.T) {
	c := NewChecker(scopePolicy(), publicResolver())

	cases := []struct {
		name       string
		raw        string
		wantReason string // "" = any rejection reason accepted
	}{
		{"javascript scheme", "javascript:alert(1)", ReasonBadScheme},
		{"data scheme", "data:text/html,x", ReasonBadScheme},
		{"userinfo trick", "https://example.com@evil.com/", ReasonUserinfo},
		{"suffix prefix trick", "https://example.com.evil.com/", ReasonOutOfScopeHost},
		{"query is not host", "https://evil.com/?next=https://example.com", ReasonOutOfScopeHost},
		{"protocol relative", "//evil.com/path", ReasonBadScheme},
		{"trailing dot out of scope", "https://example.com./", ReasonOutOfScopeHost},
		// fullwidth U+FF45 'ｅ' -> idna -> example.com (out of scope vs app.example.com)
		{"fullwidth confusable", "https://ｅxample.com/", ReasonOutOfScopeHost},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.CheckURL(tc.raw, PhaseInitial)
			assertReject(t, err, tc.wantReason)
		})
	}
}

// Verify the fullwidth host actually normalizes to example.com (and would be
// allowed if example.com were in scope), proving the rejection is by scope and
// not by an IDNA error.
func TestCheckURL_FullwidthNormalizesToExampleCom(t *testing.T) {
	p := scopePolicy()
	p.AllowedHosts = []string{"example.com"}
	c := NewChecker(p, publicResolver())

	su, err := c.CheckURL("https://ｅxample.com/", PhaseInitial)
	if err != nil {
		t.Fatalf("expected fullwidth host to normalize and pass, got %v", err)
	}
	if su.Origin.Host != "example.com" {
		t.Fatalf("normalized host = %q, want %q", su.Origin.Host, "example.com")
	}
}

// --- IP-literal blocking (skip DNS) ------------------------------------------

func TestCheckURL_IPLiteralBlocked(t *testing.T) {
	c := NewChecker(ipPolicy(), publicResolver())

	cases := []struct {
		name string
		raw  string
	}{
		{"decimal loopback", "http://2130706433/"},
		{"octal loopback", "http://017700000001/"},
		{"short form loopback", "http://127.1/"},
		{"ipv4-mapped ipv6 loopback", "http://[::ffff:127.0.0.1]/"},
		{"cloud metadata", "http://169.254.169.254/"},
		{"dotted loopback", "http://127.0.0.1/"},
		{"rfc1918 private", "http://10.0.0.1/"},
		{"link local", "http://169.254.1.1/"},
		{"hex loopback", "http://0x7f.0.0.1/"},
		{"ipv6 loopback", "http://[::1]/"},
		// IPv4-compatible IPv6 of 127.0.0.1 (::a.b.c.d). net.ParseIP yields ::7f00:1
		// whose To4() is nil, so it must be decoded via the embedded v4 and blocked
		// as loopback — not accepted as an unclassified v6 (SSRF-to-loopback bypass).
		{"ipv4-compatible ipv6 loopback", "http://[::127.0.0.1]/"},
		{"ipv4-compatible ipv6 loopback hex", "http://[::7f00:1]/"},
		{"ipv4-compatible ipv6 loopback long", "http://[0:0:0:0:0:0:127.0.0.1]/"},
		// IPv4-compatible IPv6 of 169.254.169.254 (cloud metadata / link-local).
		{"ipv4-compatible ipv6 metadata", "http://[::a9fe:a9fe]/"},
		// NAT64 well-known prefix (64:ff9b::/96) of 169.254.169.254.
		{"nat64 metadata", "http://[64:ff9b::a9fe:a9fe]/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.CheckURL(tc.raw, PhaseInitial)
			assertReject(t, err, ReasonBlockedIP)
		})
	}
}

// Internal assessment opt-in lets an otherwise-blocked IP through.
func TestCheckURL_InternalAssessmentAllowsBlocked(t *testing.T) {
	p := ipPolicy()
	p.InternalAssessment = true
	c := NewChecker(p, publicResolver())

	su, err := c.CheckURL("http://127.0.0.1/", PhaseInitial)
	if err != nil {
		t.Fatalf("internal assessment should allow loopback, got %v", err)
	}
	if len(su.PinnedIP) != 1 || !su.PinnedIP[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("pinned IP = %v, want [127.0.0.1]", su.PinnedIP)
	}
}

// --- Origin equality decision table ------------------------------------------

func TestOrigin_Equality(t *testing.T) {
	mustOrigin := func(raw string) Origin {
		o, ok := ParseOrigin(raw)
		if !ok {
			t.Fatalf("ParseOrigin(%q) failed", raw)
		}
		return o
	}

	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"https default port equiv", "https://app.example.com", "https://app.example.com:443", true},
		{"http default port equiv", "http://app.example.com", "http://app.example.com:80", true},
		{"port mismatch", "https://app.example.com:8443", "https://app.example.com", false},
		{"subdomain != parent", "https://sub.app.example.com", "https://app.example.com", false},
		{"scheme mismatch", "http://app.example.com", "https://app.example.com", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := mustOrigin(tc.a), mustOrigin(tc.b)
			if got := a.Equal(b); got != tc.want {
				t.Fatalf("%s.Equal(%s) = %v, want %v", a, b, got, tc.want)
			}
		})
	}
}

// --- Host-matching decision table --------------------------------------------

func TestHostMatching_DecisionTable(t *testing.T) {
	cases := []struct {
		name     string
		host     string
		hosts    []string
		suffixes []string
		want     bool
	}{
		{"exact host allow", "app.example.com", []string{"app.example.com"}, nil, true},
		{"suffix allow at boundary", "app.example.com", nil, []string{".example.com"}, true},
		{"apex matches suffix", "example.com", nil, []string{".example.com"}, true},
		{"suffix not at boundary", "x.example.com.attacker.net", nil, []string{".example.com"}, false},
		{"prefix confusable", "notexample.com", nil, []string{".example.com"}, false},
		{"exact rejects subdomain", "evil.app.example.com", []string{"app.example.com"}, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Checker{Policy: URLPolicy{AllowedHosts: tc.hosts, AllowedHostSuffixes: tc.suffixes}}
			if got := c.hostAllowed(tc.host); got != tc.want {
				t.Fatalf("hostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// Drive the suffix path through CheckURL end-to-end, including the adversarial
// "label boundary" reject.
func TestCheckURL_SuffixScope(t *testing.T) {
	p := scopePolicy()
	p.AllowedHosts = nil
	p.AllowedHostSuffixes = []string{".example.com"}
	c := NewChecker(p, publicResolver())

	if _, err := c.CheckURL("https://app.example.com/", PhaseInitial); err != nil {
		t.Fatalf("app.example.com should match .example.com suffix, got %v", err)
	}
	_, err := c.CheckURL("https://x.example.com.attacker.net/", PhaseInitial)
	assertReject(t, err, ReasonOutOfScopeHost)
}

// --- Positive path -----------------------------------------------------------

func TestCheckURL_PositivePinsIP(t *testing.T) {
	c := NewChecker(scopePolicy(), publicResolver())

	su, err := c.CheckURL("https://app.example.com/path", PhaseInitial)
	if err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	want := Origin{Scheme: "https", Host: "app.example.com", Port: 443}
	if !su.Origin.Equal(want) {
		t.Fatalf("origin = %v, want %v", su.Origin, want)
	}
	if len(su.PinnedIP) != 1 || !su.PinnedIP[0].Equal(net.ParseIP("93.184.216.34")) {
		t.Fatalf("pinned IP = %v, want [93.184.216.34]", su.PinnedIP)
	}
	if su.URL.Path != "/path" {
		t.Fatalf("path = %q, want /path", su.URL.Path)
	}
}

// A host that passes scope but resolves to a blocked IP is rejected (DNS
// rebinding / private-IP drift resistance).
func TestCheckURL_ResolvedToBlockedIP(t *testing.T) {
	c := NewChecker(scopePolicy(), fakeResolver{ips: []net.IP{net.ParseIP("10.0.0.5")}})

	_, err := c.CheckURL("https://app.example.com/", PhaseInitial)
	assertReject(t, err, ReasonBlockedIP)
}

func TestCheckURL_Unresolvable(t *testing.T) {
	c := NewChecker(scopePolicy(), fakeResolver{err: errors.New("nxdomain")})

	_, err := c.CheckURL("https://app.example.com/", PhaseInitial)
	assertReject(t, err, ReasonUnresolvable)
}

// --- Redirect re-check -------------------------------------------------------

func TestCheckRedirect(t *testing.T) {
	p := scopePolicy()
	p.AllowRedirects = true
	c := NewChecker(p, publicResolver())

	if err := c.CheckRedirect("https://app.example.com/a", "https://app.example.com/b"); err != nil {
		t.Fatalf("in-scope redirect should pass, got %v", err)
	}
	// Redirect to an out-of-scope host is rejected by re-running the full policy.
	assertReject(t, c.CheckRedirect("https://app.example.com/a", "https://evil.com/"), ReasonOutOfScopeHost)
	// Redirect to a blocked IP literal is rejected.
	assertReject(t, c.CheckRedirect("https://app.example.com/a", "http://127.0.0.1/"), ReasonBlockedIP)

	// When redirects are disallowed, even an in-scope hop is rejected.
	p2 := scopePolicy()
	p2.AllowRedirects = false
	c2 := NewChecker(p2, publicResolver())
	assertReject(t, c2.CheckRedirect("https://app.example.com/a", "https://app.example.com/b"), ReasonTooManyRedirect)
}

// A bounded redirect chain: with MaxRedirects=2, the first two in-scope hops
// pass and every hop thereafter is rejected with ReasonTooManyRedirect, so a
// redirect loop / unbounded chain can never run forever (Hole 3 regression).
func TestCheckRedirect_MaxRedirects(t *testing.T) {
	p := scopePolicy()
	p.AllowRedirects = true
	p.MaxRedirects = 2
	c := NewChecker(p, publicResolver())
	c.ResetRedirects()

	// Hops 1 and 2 are within the budget.
	if err := c.CheckRedirect("https://app.example.com/a", "https://app.example.com/b"); err != nil {
		t.Fatalf("hop 1 should pass, got %v", err)
	}
	if err := c.CheckRedirect("https://app.example.com/b", "https://app.example.com/c"); err != nil {
		t.Fatalf("hop 2 should pass, got %v", err)
	}
	// Every subsequent hop (here driven 100 times like a redirect loop) is
	// rejected once the chain exceeds MaxRedirects.
	for i := 0; i < 100; i++ {
		err := c.CheckRedirect("https://app.example.com/c", "https://app.example.com/d")
		assertReject(t, err, ReasonTooManyRedirect)
	}

	// ResetRedirects starts a fresh chain, so the budget is available again.
	c.ResetRedirects()
	if err := c.CheckRedirect("https://app.example.com/a", "https://app.example.com/b"); err != nil {
		t.Fatalf("hop 1 after reset should pass, got %v", err)
	}
}

// Per-range Block* flags are honored independently of the global
// InternalAssessment escape hatch: turning a single flag off un-blocks exactly
// that range while every other range stays blocked (Hole 4 regression).
func TestCheckURL_PerRangeBlockFlags(t *testing.T) {
	// BlockLoopback=false should permit 127.0.0.1 while private stays blocked.
	p := ipPolicy()
	p.BlockLoopback = false
	c := NewChecker(p, publicResolver())

	su, err := c.CheckURL("http://127.0.0.1/", PhaseInitial)
	if err != nil {
		t.Fatalf("BlockLoopback=false should permit loopback, got %v", err)
	}
	if len(su.PinnedIP) != 1 || !su.PinnedIP[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("pinned IP = %v, want [127.0.0.1]", su.PinnedIP)
	}
	// The other ranges are still blocked under the same policy.
	if _, err := c.CheckURL("http://10.0.0.1/", PhaseInitial); err == nil {
		t.Fatalf("BlockPrivateIPs=true should still block 10.0.0.1")
	} else {
		assertReject(t, err, ReasonBlockedIP)
	}

	// Conversely, BlockPrivateIPs=false permits 10.0.0.1 but loopback stays blocked.
	p2 := ipPolicy()
	p2.BlockPrivateIPs = false
	c2 := NewChecker(p2, publicResolver())
	if _, err := c2.CheckURL("http://10.0.0.1/", PhaseInitial); err != nil {
		t.Fatalf("BlockPrivateIPs=false should permit 10.0.0.1, got %v", err)
	}
	assertReject(t, mustErr(c2.CheckURL("http://127.0.0.1/", PhaseInitial)), ReasonBlockedIP)
}

// mustErr discards the SafeURL and returns only the error, for inline assertions.
func mustErr(_ *SafeURL, err error) error { return err }

// An ASCII label containing an underscore is tolerated even when a sibling label
// is unicode: the host is IDNA-mapped (the unicode label is punycoded) without
// the STD3 hostname rule rejecting '_' (Hole 5 regression). The rejection, if
// any, must be by scope — not ReasonBadHost.
func TestCheckURL_UnderscoreIDNHost(t *testing.T) {
	p := scopePolicy()
	// Put the punycoded form of srv_münchen.example.com in scope so a pass proves
	// the underscore did not cause an IDNA rejection.
	p.AllowedHosts = []string{"xn--srv_mnchen-eeb.example.com"}
	c := NewChecker(p, publicResolver())

	su, err := c.CheckURL("https://srv_münchen.example.com/", PhaseInitial)
	if err != nil {
		// A ReasonBadHost here is the bug being regressed against.
		t.Fatalf("underscore+IDN host should not be rejected as bad host, got %v", err)
	}
	if su.Origin.Host != "xn--srv_mnchen-eeb.example.com" {
		t.Fatalf("normalized host = %q, want xn--srv_mnchen-eeb.example.com", su.Origin.Host)
	}

	// And it must NOT be rejected with ReasonBadHost when out of the configured
	// scope: a different scope yields ReasonOutOfScopeHost, proving IDNA succeeded.
	p2 := scopePolicy() // AllowedHosts = app.example.com
	c2 := NewChecker(p2, publicResolver())
	_, err = c2.CheckURL("https://srv_münchen.example.com/", PhaseInitial)
	assertReject(t, err, ReasonOutOfScopeHost)
}

// --- Extra adversarial bypass cases ------------------------------------------

func TestCheckURL_AdversarialBypass(t *testing.T) {
	c := NewChecker(scopePolicy(), publicResolver())

	cases := []struct {
		name       string
		raw        string
		wantReason string
	}{
		// 1. Backslash + userinfo host trick — net/url rejects the malformed
		// userinfo before any host comparison; it must never be accepted as
		// in-scope app.example.com.
		{"backslash userinfo", "https://app.example.com\\@evil.com/", ReasonUnparseable},
		// 2. Mixed-case scheme must be lower-cased and still scope-checked.
		{"mixed case scheme bad", "HtTpS://evil.com/", ReasonOutOfScopeHost},
		// 3. Encoded-dot host: %2e is an invalid escape in the authority, so
		// net/url rejects it rather than silently decoding "app.example.com".
		{"encoded dot host", "https://app%2eexample.com/", ReasonUnparseable},
		// 4. Port 0 is not in AllowedPorts(443).
		{"port zero", "https://app.example.com:0/", ReasonBadPort},
		// 5. Embedded control char (tab) inside the URL is rejected up front.
		{"embedded tab", "https://app.example.com\t/", ReasonControlChar},
		// 6. Embedded newline.
		{"embedded newline", "https://app.example.com\n/", ReasonControlChar},
		// 7. CRLF host-header smuggling attempt.
		{"crlf smuggle", "https://app.example.com\r\nHost: evil.com/", ReasonControlChar},
		// 8. Disallowed explicit port even on the right host.
		{"wrong explicit port", "https://app.example.com:8443/", ReasonBadPort},
		// 9. Empty host (scheme but no authority host).
		{"empty host", "https:///path", ReasonEmptyHost},
		// 10. Whitespace-padded URL is trimmed, then handled normally.
		{"leading whitespace evil", "   https://evil.com/", ReasonOutOfScopeHost},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.CheckURL(tc.raw, PhaseInitial)
			assertReject(t, err, tc.wantReason)
		})
	}
}

// Mixed-case scheme on an IN-scope host must succeed (scheme is lower-cased).
func TestCheckURL_MixedCaseSchemeInScope(t *testing.T) {
	c := NewChecker(scopePolicy(), publicResolver())
	su, err := c.CheckURL("HTTPS://APP.Example.COM/", PhaseInitial)
	if err != nil {
		t.Fatalf("mixed-case scheme+host in scope should pass, got %v", err)
	}
	if su.Origin.Scheme != "https" || su.Origin.Host != "app.example.com" {
		t.Fatalf("origin = %v, want https://app.example.com", su.Origin)
	}
}

// --- ClassifyIP unit table ---------------------------------------------------

func TestClassifyIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
		reason  string
	}{
		{"127.0.0.1", true, ipReasonLoopback},
		{"::1", true, ipReasonLoopback},
		{"10.1.2.3", true, ipReasonPrivate},
		{"172.16.0.1", true, ipReasonPrivate},
		{"192.168.1.1", true, ipReasonPrivate},
		{"169.254.0.1", true, ipReasonLinkLocal},
		{"fe80::1", true, ipReasonLinkLocal},
		// 224.0.0.0/24 and ff02::/16 are link-local multicast — the more specific
		// link_local reason wins by design.
		{"224.0.0.1", true, ipReasonLinkLocal},
		{"ff02::1", true, ipReasonLinkLocal},
		// Globally-scoped multicast falls through to the multicast reason.
		{"239.1.2.3", true, ipReasonMulticast},
		{"ff0e::1", true, ipReasonMulticast},
		{"0.0.0.0", true, ipReasonUnspecified},
		{"::", true, ipReasonUnspecified},
		{"169.254.169.254", true, ipReasonCloudMeta},
		{"::ffff:10.0.0.1", true, ipReasonPrivate},
		{"::ffff:127.0.0.1", true, ipReasonLoopback},
		{"fc00::1", true, ipReasonUniqueLocal},
		// IPv4-compatible IPv6 (::a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) embed a v4
		// that To4() does not collapse; they must classify by the embedded v4 range.
		{"::127.0.0.1", true, ipReasonLoopback},
		{"::a9fe:a9fe", true, ipReasonCloudMeta},        // 169.254.169.254
		{"::a9fe:101", true, ipReasonLinkLocal},         // 169.254.1.1
		{"::a00:1", true, ipReasonPrivate},              // 10.0.0.1
		{"64:ff9b::a9fe:a9fe", true, ipReasonCloudMeta}, // NAT64 169.254.169.254
		{"64:ff9b::7f00:1", true, ipReasonLoopback},     // NAT64 127.0.0.1
		{"64:ff9b::5db8:d822", false, ""},               // NAT64 of public 93.184.216.34
		{"93.184.216.34", false, ""},
		{"8.8.8.8", false, ""},
		{"2606:2800:220:1::1", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test IP %q", tc.ip)
			}
			blocked, reason := ClassifyIP(ip)
			if blocked != tc.blocked {
				t.Fatalf("ClassifyIP(%s) blocked = %v, want %v", tc.ip, blocked, tc.blocked)
			}
			if tc.blocked && reason != tc.reason {
				t.Fatalf("ClassifyIP(%s) reason = %q, want %q", tc.ip, reason, tc.reason)
			}
		})
	}
}

// --- ParseHostIP unit table --------------------------------------------------

func TestParseHostIP(t *testing.T) {
	cases := []struct {
		host   string
		wantIP string // "" = not an IP
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"2130706433", "127.0.0.1"},   // decimal
		{"017700000001", "127.0.0.1"}, // octal (single part)
		{"0x7f000001", "127.0.0.1"},   // hex (single part)
		{"127.1", "127.0.0.1"},        // short form
		{"127.0.1", "127.0.0.1"},      // 3-part short form
		{"0x7f.0.0.1", "127.0.0.1"},   // mixed hex part
		{"0177.0.0.1", "127.0.0.1"},   // octal part
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
		{"app.example.com", ""}, // hostname
		{"example", ""},         // bare label, not numeric
		{"256.0.0.1", ""},       // out of range octet
		{"1.2.3.4.5", ""},       // too many parts
		{"0x", ""},              // empty hex
		{"99999999999", ""},     // > 32 bits
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			ip, ok := ParseHostIP(tc.host)
			if tc.wantIP == "" {
				if ok {
					t.Fatalf("ParseHostIP(%q) = %v, want not-an-IP", tc.host, ip)
				}
				return
			}
			if !ok {
				t.Fatalf("ParseHostIP(%q) failed, want %s", tc.host, tc.wantIP)
			}
			if !ip.Equal(net.ParseIP(tc.wantIP)) {
				t.Fatalf("ParseHostIP(%q) = %v, want %s", tc.host, ip, tc.wantIP)
			}
		})
	}
}
