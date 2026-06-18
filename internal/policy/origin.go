package policy

import (
	"net/url"
	"strconv"
	"strings"
)

// defaultPort returns the default port for a known scheme. The boolean reports
// whether the scheme is recognized.
func defaultPort(scheme string) (int, bool) {
	switch scheme {
	case "http":
		return 80, true
	case "https":
		return 443, true
	default:
		return 0, false
	}
}

// OriginFromURL derives a normalized Origin from a parsed URL. The scheme is
// lower-cased, the host is taken verbatim from u.Hostname() (callers are
// expected to have normalized it already), and the port is filled with the
// scheme default when the URL omits it. The boolean is false when the scheme is
// unknown or the host is empty, in which case origin comparison would be
// ambiguous.
func OriginFromURL(u *url.URL) (Origin, bool) {
	if u == nil {
		return Origin{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if host == "" {
		return Origin{}, false
	}

	def, known := defaultPort(scheme)
	if !known {
		return Origin{}, false
	}

	port := def
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			return Origin{}, false
		}
		port = n
	}

	return Origin{Scheme: scheme, Host: host, Port: port}, true
}

// ParseOrigin parses a raw origin string (e.g. "https://app.example.com" or
// "http://host:8080") into a normalized Origin. It applies the same default-port
// filling as OriginFromURL. The boolean is false when the input cannot be parsed
// into a complete origin.
func ParseOrigin(raw string) (Origin, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Origin{}, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Origin{}, false
	}
	// A bare "host:port" parses with an empty scheme; require an explicit scheme
	// so the default port is unambiguous.
	if u.Scheme == "" || u.Host == "" {
		return Origin{}, false
	}
	// Normalize the host the same way the canonicalizer does (lower-case, strip a
	// single trailing dot) so ParseOrigin agrees with CheckURL. Capture the port
	// before rewriting u.Host, since u.Port() reads from u.Host.
	host := strings.ToLower(u.Hostname())
	host = strings.TrimSuffix(host, ".")
	port := u.Port()
	if port != "" {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}
	return OriginFromURL(u)
}
