package authstate

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/lexdotdev/nocapsec/internal/policy"
)

// ErrOriginNotAllowed means the origin is blocked.
var ErrOriginNotAllowed = errors.New("authstate: origin not allowed")

// InjectHeaders copies headers,
// only for an allowed origin.
func InjectHeaders(state *AuthState, creds *Credentials, targetOrigin string) (map[string]string, error) {
	if !originAllowed(state, targetOrigin) {
		return nil, ErrOriginNotAllowed
	}
	out := make(map[string]string, len(creds.Headers))
	for k, v := range creds.Headers {
		out[k] = v
	}
	return out, nil
}

// InjectCookieJar adds cookies,
// only for an allowed origin.
func InjectCookieJar(state *AuthState, creds *Credentials, jar http.CookieJar, targetOrigin string) error {
	if !originAllowed(state, targetOrigin) {
		return ErrOriginNotAllowed
	}
	u, err := url.Parse(targetOrigin)
	if err != nil {
		return err
	}
	cookies := make([]*http.Cookie, len(creds.Cookies))
	for i, c := range creds.Cookies {
		cookies[i] = &http.Cookie{
			Name:   c.Name,
			Value:  c.Value,
			Domain: c.Domain,
			Path:   c.Path,
		}
	}
	jar.SetCookies(u, cookies)
	return nil
}

// originAllowed reports if origin is allowed.
func originAllowed(state *AuthState, targetOrigin string) bool {
	target, ok := policy.ParseOrigin(targetOrigin)
	if !ok {
		return false
	}
	for _, allowed := range state.AllowedOrigins {
		o, ok := policy.ParseOrigin(allowed)
		if !ok {
			continue
		}
		if o.Equal(target) {
			return true
		}
	}
	return false
}
