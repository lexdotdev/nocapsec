package policy

import (
	"math/big"
	"net"
	"strings"
)

// Blocked-range reason sub-codes. ClassifyIP returns one of these strings as the
// human-readable reason; the caller maps the whole rejection to ReasonBlockedIP.
const (
	ipReasonLoopback    = "loopback"
	ipReasonPrivate     = "rfc1918_private"
	ipReasonLinkLocal   = "link_local"
	ipReasonMulticast   = "multicast"
	ipReasonUnspecified = "unspecified"
	ipReasonCloudMeta   = "cloud_metadata"
	ipReasonUniqueLocal = "unique_local"
)

// cloudMetadataV4 is the canonical IMDS endpoint shared by AWS/GCP/Azure/etc.
var cloudMetadataV4 = net.IPv4(169, 254, 169, 254)

// cloudMetadataV6 is the AWS IPv6 metadata endpoint (fd00:ec2::254).
var cloudMetadataV6 = net.ParseIP("fd00:ec2::254")

// fc00 (fc00::/7) — IPv6 unique-local addresses. Treated as private.
var (
	_, uniqueLocalNet, _ = net.ParseCIDR("fc00::/7")
)

// nat64Prefix is the well-known NAT64 prefix (64:ff9b::/96, RFC 6052). An address
// in this prefix embeds an IPv4 address in its low 32 bits, so 64:ff9b::a.b.c.d
// reaches the same host as a.b.c.d once translated. We must classify the embedded
// v4 so a NAT64-routed address cannot bypass a blocked v4 range.
var nat64Prefix = [12]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}

// embeddedV4 extracts an IPv4 address embedded in certain IPv6 forms that
// net.IP.To4() does NOT collapse to v4 on its own, so they would otherwise escape
// range classification:
//
//   - IPv4-compatible IPv6 (::a.b.c.d, RFC 4291): the upper 96 bits are zero and
//     the low 32 bits carry the v4. net.ParseIP("::127.0.0.1") yields ::7f00:1
//     with To4()==nil. We exclude :: (unspecified) and ::1 (loopback) and the
//     reserved ::0.0.0.x block by requiring a non-zero leading v4 octet.
//   - NAT64 well-known prefix (64:ff9b::/96, RFC 6052): the low 32 bits carry the
//     embedded v4.
//
// It returns the embedded v4 (4-byte form) and true when ip is one of these
// forms; otherwise (nil, false). IPv4-mapped IPv6 (::ffff:a.b.c.d) is NOT handled
// here because net.IP.To4() already collapses it upstream.
func embeddedV4(ip net.IP) (net.IP, bool) {
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, false
	}
	v4 := net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15]).To4()

	// NAT64 well-known prefix: 64:ff9b:: with the v4 in the low 32 bits.
	isNAT64 := true
	for i := 0; i < 12; i++ {
		if ip16[i] != nat64Prefix[i] {
			isNAT64 = false
			break
		}
	}
	if isNAT64 {
		return v4, true
	}

	// IPv4-compatible IPv6: upper 96 bits zero, low 32 bits a routable-looking v4.
	for i := 0; i < 12; i++ {
		if ip16[i] != 0 {
			return nil, false
		}
	}
	// Exclude ::, ::1, and the reserved ::0.0.0.x block. A genuine IPv4-compatible
	// address has a non-zero leading octet (e.g. 127.x, 169.254.x, 10.x).
	if ip16[12] == 0 {
		return nil, false
	}
	return v4, true
}

// ClassifyIP reports whether an IP falls in a blocked range and, if so, a stable
// reason sub-code. The classification operates on the canonical net.IP, so any
// alternate textual encoding that ParseHostIP normalized to the same address is
// classified identically. Cloud-metadata is checked before the broader
// link-local range so the most specific reason wins.
func ClassifyIP(ip net.IP) (blocked bool, reason string) {
	if ip == nil {
		return true, ipReasonUnspecified
	}

	// Normalize an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its v4 form so a
	// mapped private/loopback address is classified by its real v4 range.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else if v4, ok := embeddedV4(ip); ok {
		// IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) forms embed a
		// v4 address that To4() does not collapse. Classify the embedded v4 so the
		// address is blocked by its real range (loopback, link-local, cloud
		// metadata, etc.) instead of slipping through as an unclassified v6.
		ip = v4
	}

	// Cloud metadata — most specific, check first.
	if ip.Equal(cloudMetadataV4) || (cloudMetadataV6 != nil && ip.Equal(cloudMetadataV6)) {
		return true, ipReasonCloudMeta
	}

	if ip.IsUnspecified() {
		return true, ipReasonUnspecified
	}
	if ip.IsLoopback() {
		return true, ipReasonLoopback
	}
	// Link-local (169.254.0.0/16, fe80::/10). Checked before multicast so the
	// more specific reason wins for link-local multicast addresses too.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, ipReasonLinkLocal
	}
	if ip.IsMulticast() {
		return true, ipReasonMulticast
	}
	if ip.IsPrivate() {
		// IsPrivate covers RFC1918 (v4) and fc00::/7 (v6 ULA).
		if ip.To4() != nil {
			return true, ipReasonPrivate
		}
		return true, ipReasonUniqueLocal
	}
	// Defensive: catch fc00::/7 explicitly in case of stdlib differences.
	if uniqueLocalNet != nil && uniqueLocalNet.Contains(ip) {
		return true, ipReasonUniqueLocal
	}

	return false, ""
}

// ipBlockedByPolicy reports whether ip is blocked for this Checker, honoring the
// per-range Block* flags. ClassifyIP performs the (policy-independent) range
// classification; this method then consults the corresponding Block* flag so an
// operator can un-block a single range (e.g. BlockLoopback=false to permit
// 127.0.0.1) without flipping InternalAssessment, which un-blocks everything.
//
// InternalAssessment short-circuits to "not blocked" for every range, preserving
// the existing global opt-in. When a Block* flag is false, that specific range is
// allowed; all other ranges remain blocked. Direction is fail-closed: an
// unrecognized reason is treated as blocked.
func (c *Checker) ipBlockedByPolicy(ip net.IP) (bool, string) {
	blocked, reason := ClassifyIP(ip)
	if !blocked {
		return false, ""
	}
	if c.Policy.InternalAssessment {
		return false, reason
	}
	switch reason {
	case ipReasonLoopback:
		return c.Policy.BlockLoopback, reason
	case ipReasonPrivate, ipReasonUniqueLocal:
		return c.Policy.BlockPrivateIPs, reason
	case ipReasonLinkLocal:
		return c.Policy.BlockLinkLocal, reason
	case ipReasonMulticast:
		return c.Policy.BlockMulticast, reason
	case ipReasonUnspecified:
		return c.Policy.BlockUnspecified, reason
	case ipReasonCloudMeta:
		return c.Policy.BlockCloudMetadata, reason
	default:
		return true, reason
	}
}

// ParseHostIP interprets a URL host as an IP literal, accepting the inet_aton /
// libc-style alternate encodings that browsers and many HTTP stacks normalize
// but net/url leaves as an opaque host string. It returns the canonical net.IP
// and true when the host is an IP literal; otherwise it returns false and the
// host should be treated as a DNS name.
//
// Accepted forms:
//   - bracketed IPv6: "[::1]" (brackets already stripped by url.Hostname, but we
//     also accept a raw colon-bearing IPv6 string)
//   - dotted IPv4 with 1–4 parts, each part decimal/octal(0…)/hex(0x…):
//     "127.0.0.1", "127.1", "0x7f.1", "017700000001" (single part), "2130706433"
func ParseHostIP(host string) (net.IP, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, false
	}

	// Bracketed or raw IPv6.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if strings.Contains(host, ":") {
		if ip := net.ParseIP(host); ip != nil {
			return ip, true
		}
		return nil, false
	}

	// Pure dotted-decimal fast path (and the canonical form).
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, true
		}
		return ip, true
	}

	// inet_aton-style: 1–4 numeric parts, each decimal/octal/hex.
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil, false
	}

	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, false
		}
		v, ok := parseInetAtonPart(p)
		if !ok {
			return nil, false
		}
		vals[i] = v
	}

	// Per inet_aton: the last part absorbs all remaining low-order bytes; every
	// earlier part must fit in a single byte.
	var n uint64
	switch len(vals) {
	case 1:
		// a — whole 32-bit value.
		n = vals[0]
		if n > 0xFFFFFFFF {
			return nil, false
		}
	case 2:
		// a.b — a<<24 | b(24 bits)
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return nil, false
		}
		n = vals[0]<<24 | vals[1]
	case 3:
		// a.b.c — a<<24 | b<<16 | c(16 bits)
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return nil, false
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4:
		// a.b.c.d — each one byte.
		for _, v := range vals {
			if v > 0xFF {
				return nil, false
			}
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	}

	if n > 0xFFFFFFFF {
		return nil, false
	}
	ip := net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return ip.To4(), true
}

// parseInetAtonPart parses one part of an inet_aton address as decimal, octal
// (leading 0), or hexadecimal (leading 0x/0X). It uses big.Int only to reject
// overflow cleanly without panicking; values larger than 32 bits are rejected by
// the caller.
func parseInetAtonPart(p string) (uint64, bool) {
	base := 10
	digits := p
	switch {
	case len(p) >= 2 && (p[0] == '0') && (p[1] == 'x' || p[1] == 'X'):
		base = 16
		digits = p[2:]
		if digits == "" {
			return 0, false
		}
	case len(p) >= 2 && p[0] == '0':
		base = 8
		digits = p[1:]
	case p == "0":
		return 0, true
	}

	// Validate digit set for the chosen base and accumulate via big.Int to avoid
	// overflow surprises, then bound-check to 32 bits.
	bi, ok := new(big.Int).SetString(digits, base)
	if !ok {
		return 0, false
	}
	if bi.Sign() < 0 {
		return 0, false
	}
	if bi.BitLen() > 32 {
		return 0, false
	}
	return bi.Uint64(), true
}
