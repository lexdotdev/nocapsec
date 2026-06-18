package evidence

// schema.go holds the JSON schema for findings: the global field set plus the
// per-type evidence/proof sub-schemas. cmd/verifierd loads the compiled union
// at startup and hands it to the normalizer.
//
// TODO: implement the finding JSON schema (global fields + per-type shapes) and
// strict-mode unknown-field rejection.
// See specs/domains/evidence/README.md (Key Files, Configuration) and
// specs/contracts/evidence-contract.md (Global Fields, Initialization).
