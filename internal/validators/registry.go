package validators

// registry maps a finding type string to the validator that handles it. It is
// populated by each validator's init function.
var registry = map[string]Validator{}

// Register adds v to the registry under v.Type(). It is called from init
// functions; a duplicate type silently overwrites the earlier registration.
func Register(v Validator) {
	registry[v.Type()] = v
}

// Lookup returns the validator registered for type t, and whether one exists.
func Lookup(t string) (Validator, bool) {
	v, ok := registry[t]
	return v, ok
}
