package validators

// registry maps finding type to validator.
var registry = map[string]Validator{}

// Register adds v under v.Type(); dupes overwrite.
func Register(v Validator) {
	registry[v.Type()] = v
}

// Lookup returns the validator for type t.
func Lookup(t string) (Validator, bool) {
	v, ok := registry[t]
	return v, ok
}
