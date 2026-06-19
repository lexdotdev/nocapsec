package authstate

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/lexdotdev/nocapsec/internal/policy"
)

// ErrOriginNotAllowed is returned when injection targets a non-allowed origin.
var ErrOriginNotAllowed = errors.New("authstate: origin not allowed")

// InjectHeaders returns a copy of the credentials' headers suitable for the
// given origin. Returns ErrOriginNotAllowed if the origin is not in the
// state's AllowedOrigins.
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

// InjectCookieJar adds the credential cookies into jar, but only for origins
// that are in AllowedOrigins. Returns ErrOriginNotAllowed if targetOrigin is
// not in the state's list.
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

// originAllowed checks if origin is in AllowedOrigins.
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
