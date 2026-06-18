package authstate

// Redact removes secret material from a byte slice before it is written to a
// log or stored artifact.
//
// TODO: redact Cookie, Authorization, Set-Cookie, CSRF tokens, and bearer-like
// values from all stored artifacts and logs per
// specs/domains/authstate/README.md and
// specs/decisions/007-auth-state-first-class.md.
func Redact(b []byte) []byte {
	return b
}
