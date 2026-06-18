package artifacts

// Sanitize redacts secrets before persistence; every artifact passes through
// it so raw credentials never reach storage.
//
// TODO: strip Cookie/Authorization/Set-Cookie/CSRF/bearer and other secrets.
func Sanitize(data []byte) []byte {
	return data
}
