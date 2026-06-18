package evidence

// Canonicalize rewrites a parsed Finding into its canonical, replay-safe form:
// lower-cased URL hosts, normalized headers, and ordered browser steps.
// Canonicalization is lossless for replay — the normalized request reproduces
// the client's intent byte-for-byte except for declared mutation slots.
//
// TODO: implement canonicalization of requests, URLs, headers, and browser
// steps. See specs/domains/evidence/README.md (Flow, Invariants) and
// specs/contracts/evidence-contract.md (Data Flow Across Boundary).
func Canonicalize(f *Finding) error {
	return nil
}
