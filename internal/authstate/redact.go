package authstate

// Redact removes secrets before a byte slice is logged or stored.
//
// TODO: redact Cookie, Authorization, Set-Cookie, CSRF, and bearer values.
func Redact(b []byte) []byte {
	return b
}
