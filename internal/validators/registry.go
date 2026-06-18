package validators

// registry maps a finding type to its validator, populated by init functions.
var registry = map[string]Validator{}

// Register adds v under v.Type(); a duplicate type overwrites the earlier one.
func Register(v Validator) {
	registry[v.Type()] = v
}

// Lookup returns the validator registered for type t, and whether one exists.
func Lookup(t string) (Validator, bool) {
	v, ok := registry[t]
	return v, ok
}
