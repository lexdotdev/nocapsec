package policy

import (
	"math/big"
	"net"
	"strings"
)

// Blocked-range reason sub-codes returned by ClassifyIP; the caller maps the
// rejection to ReasonBlockedIP.
const (
	ipReasonLoopback    = "loopback"
	ipReasonPrivate     = "rfc1918_private"
	ipReasonLinkLocal   = "link_local"
	ipReasonMulticast   = "multicast"
	ipReasonUnspecified = "unspecified"
	ipReasonCloudMeta   = "cloud_metadata"
	ipReasonUniqueLocal = "unique_local"
)

// cloudMetadataV4 is the canonical IMDS endpoint (AWS/GCP/Azure).
var cloudMetadataV4 = net.IPv4(169, 254, 169, 254)

// cloudMetadataV6 is the AWS IPv6 metadata endpoint.
var cloudMetadataV6 = net.ParseIP("fd00:ec2::254")

// nat64Prefix is the well-known NAT64 prefix (64:ff9b::/96). It embeds a v4 in
// the low 32 bits, so the embedded v4 must be classified to block NAT64 routes.
var nat64Prefix = [12]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}

// embeddedV4 extracts an IPv4 from IPv6 forms that To4() does not collapse, so
// they cannot escape range classification:
//
//   - IPv4-compatible IPv6 (::a.b.c.d): upper 96 bits zero, v4 in the low 32.
//     :: , ::1, and the reserved ::0.0.0.x block are excluded (non-zero leading
//     octet required).
//   - NAT64 (64:ff9b::/96): v4 in the low 32 bits.
//
// IPv4-mapped IPv6 (::ffff:a.b.c.d) is handled upstream by To4().
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

// ClassifyIP reports whether an IP is in a blocked range, with a stable reason.
// It works on the canonical net.IP; the most specific reason wins (e.g.
// cloud-metadata before link-local).
func ClassifyIP(ip net.IP) (blocked bool, reason string) {
	if ip == nil {
		return true, ipReasonUnspecified
	}
	ip = canonicalForClassify(ip)

	switch {
	case ip.Equal(cloudMetadataV4) || (cloudMetadataV6 != nil && ip.Equal(cloudMetadataV6)):
		return true, ipReasonCloudMeta
	case ip.IsUnspecified():
		return true, ipReasonUnspecified
	case ip.IsLoopback():
		return true, ipReasonLoopback
	// Link-local before multicast so the more specific reason wins for
	// link-local multicast addresses too.
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return true, ipReasonLinkLocal
	case ip.IsMulticast():
		return true, ipReasonMulticast
	case ip.IsPrivate(): // RFC1918 (v4) and fc00::/7 (v6 ULA)
		if ip.To4() != nil {
			return true, ipReasonPrivate
		}
		return true, ipReasonUniqueLocal
	}
	return false, ""
}

// canonicalForClassify collapses mapped/compatible/NAT64 IPv6 to the embedded
// v4, so an internal address cannot slip through as an unclassified v6.
func canonicalForClassify(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if v4, ok := embeddedV4(ip); ok {
		return v4
	}
	return ip
}

// ipBlockedByPolicy reports whether ip is blocked, honoring the per-range
// Block* flags. InternalAssessment un-blocks everything; otherwise each range
// follows its flag. Fail-closed: an unrecognized reason stays blocked.
func (c *Checker) ipBlockedByPolicy(ip net.IP) bool {
	blocked, reason := ClassifyIP(ip)
	if !blocked {
		return false
	}
	if c.Policy.InternalAssessment {
		return false
	}
	switch reason {
	case ipReasonLoopback:
		return c.Policy.BlockLoopback
	case ipReasonPrivate, ipReasonUniqueLocal:
		return c.Policy.BlockPrivateIPs
	case ipReasonLinkLocal:
		return c.Policy.BlockLinkLocal
	case ipReasonMulticast:
		return c.Policy.BlockMulticast
	case ipReasonUnspecified:
		return c.Policy.BlockUnspecified
	case ipReasonCloudMeta:
		return c.Policy.BlockCloudMetadata
	default:
		return true
	}
}

// ParseHostIP interprets a URL host as an IP literal, decoding the inet_aton /
// libc-style encodings net/url leaves opaque. Returns the canonical net.IP and
// true for a literal; false means treat host as a DNS name.
//
// Accepted: bracketed/raw IPv6, and dotted IPv4 with 1–4 parts each in
// decimal/octal(0…)/hex(0x…) — e.g. "127.1", "0x7f.1", "2130706433".
func ParseHostIP(host string) (net.IP, bool) { //nolint:gocyclo // ordered IP-literal decoder
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

	// inet_aton: the last part absorbs the remaining low bytes; earlier parts
	// must each fit in one byte.
	var n uint64
	switch len(vals) {
	case 1: // a — whole 32-bit value
		n = vals[0]
		if n > 0xFFFFFFFF {
			return nil, false
		}
	case 2: // a.b
		if vals[0] > 0xFF || vals[1] > 0xFFFFFF {
			return nil, false
		}
		n = vals[0]<<24 | vals[1]
	case 3: // a.b.c
		if vals[0] > 0xFF || vals[1] > 0xFF || vals[2] > 0xFFFF {
			return nil, false
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4: // a.b.c.d
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

// parseInetAtonPart parses one part as decimal, octal (leading 0), or hex
// (leading 0x). big.Int guards against overflow before the 32-bit bound-check.
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
