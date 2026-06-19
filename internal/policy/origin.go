package policy

import (
	"net/url"
	"strconv"
	"strings"
)

// OriginFromURL derives a normalized Origin from a parsed URL.
func OriginFromURL(u *url.URL) (Origin, bool) {
	if u == nil {
		return Origin{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	if host == "" {
		return Origin{}, false
	}

	var def int
	switch scheme {
	case schemeHTTP:
		def = 80
	case schemeHTTPS:
		def = 443
	default:
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

// ParseOrigin parses a raw origin string (e.g. "https://app.example.com") into
// a normalized Origin, with the same default-port filling as OriginFromURL.
func ParseOrigin(raw string) (Origin, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Origin{}, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Origin{}, false
	}
	// Require an explicit scheme so the default port is unambiguous; a bare
	// "host:port" parses with an empty scheme.
	if u.Scheme == "" || u.Host == "" {
		return Origin{}, false
	}
	// Normalize the host like CheckURL does so origins agree. Capture the port
	// first, since u.Port() reads from u.Host.
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
