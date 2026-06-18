package evidence

import "fmt"

// Parse turns an untrusted, client-authored JSON finding into a canonical,
// validated Finding. It schema-validates the input, rejects prose-only or
// insufficient findings, canonicalizes the request shapes, and verifies
// mutation-slot consistency. A finding that fails any check yields a wrapped
// ErrInvalid with a stable reason and no execution occurs.
//
// TODO: implement schema validation, canonicalization, and mutation-slot
// checks. See specs/domains/evidence/README.md (Flow, Invariants) and
// specs/contracts/evidence-contract.md (Error Propagation).
func Parse(raw []byte) (*Finding, error) {
	return nil, fmt.Errorf("%w: parsing not implemented", ErrInvalid)
}

// validateMutationSlots checks that every declared mutation slot references a
// position that actually exists in the finding's evidence. An undeclared or
// dangling slot makes the finding invalid.
//
// TODO: implement mutation-slot consistency checking against the evidence.
// See specs/domains/evidence/README.md (Invariants) and
// specs/contracts/evidence-contract.md (Error Propagation).
func validateMutationSlots(f *Finding) error {
	return nil
}
