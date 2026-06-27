package validators

import "fmt"

// Registry resolves validators by type.
type Registry struct {
	byType map[string]Validator
}

// NewRegistry validates a validator set.
func NewRegistry(vals ...Validator) (*Registry, error) {
	r := &Registry{byType: make(map[string]Validator, len(vals))}
	for _, v := range vals {
		if v == nil {
			return nil, fmt.Errorf("validators: nil validator")
		}
		typ := v.Type()
		if typ == "" {
			return nil, fmt.Errorf("validators: empty type")
		}
		if _, ok := r.byType[typ]; ok {
			return nil, fmt.Errorf("validators: duplicate type %q", typ)
		}
		r.byType[typ] = v
	}
	return r, nil
}

// DefaultRegistry returns built-in validators.
func DefaultRegistry() (*Registry, error) {
	return NewRegistry(
		xssReflected{},
		xssStored{},
		xssBlind{},
		openRedirect{},
		sqliTiming{},
		sqliBoolean{},
		sqliInband{},
		sqliUnionExtract{},
		nosqliAuthBypass{},
		sstiReflected{},
		sstiStored{},
		crlfResponseSplitting{},
		cachePoisoning{},
		ssrfOAST{},
		xxeOAST{},
		commandInjectionTiming{},
		commandInjectionOAST{},
		pathTraversal{},
		idorRead{},
	)
}

// Lookup returns the validator for type t.
func (r *Registry) Lookup(t string) (Validator, bool) {
	if r == nil {
		return nil, false
	}
	v, ok := r.byType[t]
	return v, ok
}

// Lookup returns a built-in validator.
func Lookup(t string) (Validator, bool) {
	r, err := DefaultRegistry()
	if err != nil {
		return nil, false
	}
	return r.Lookup(t)
}
