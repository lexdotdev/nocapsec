package validators

// registry maps type to validator.
var registry = map[string]Validator{}

// Register adds v by type.
func Register(v Validator) {
	registry[v.Type()] = v
}

// Lookup returns the validator for type t.
func Lookup(t string) (Validator, bool) {
	v, ok := registry[t]
	return v, ok
}
