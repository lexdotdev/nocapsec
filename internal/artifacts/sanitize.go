package artifacts

// Sanitize redacts secrets from data before it is persisted. Every artifact
// must pass through Sanitize so that raw credentials never reach storage.
//
// TODO: implement redaction per specs/domains/artifacts/README.md and
// specs/architecture/security-model.md — strip Cookie/Authorization/
// Set-Cookie/CSRF/bearer values and other secret classes from
// specs/domains/authstate/README.md before persistence.
func Sanitize(data []byte) []byte {
	return data
}
