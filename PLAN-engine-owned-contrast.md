# Implementation Plan: Engine-Owned Differential Contrast (Tier 1)

Ready to implement. Decision recorded in [ADR-010](specs/decisions/010-engine-owned-differential-contrast.md).

## Goal

Remove the differential validators' dependence on client-authored contrast. The client supplies one base request, one declared injection location, and per-arm payload VALUES; the engine builds every arm by mutating only that slot. This makes the "three unrelated requests" cheat structurally impossible, makes the injection location load-bearing, and shrinks the bundle — with no SQL/shell parsing.

Scope: `sqli.boolean_based`, `sqli.time_based`, `command_injection.time_based`. Clean cutover (no dual shape). Out of scope: OAST attribution, auth executor, target attestation (see ADR-010 Alternatives).

## New evidence shape

Boolean:

```json
"evidence": {
  "base_request": { "method": "...", "url": "...", "headers": [], "body": "..." },
  "injection": {
    "location": { "kind": "query|form|json_body", "name": "id", "json_pointer": "/x" },
    "payloads": { "baseline": "1", "true_condition": "1 AND 1=1", "false_condition": "1 AND 1=2" }
  }
}
```

Timing (sqli + cmdi): same, with `payloads` keys `control` / `delay_low` / `delay_high`.

Rules: `kind=query|form` needs `name`; `json_body` needs `json_pointer`. The named position MUST exist in `base_request` (for `query`, the param must already be in the URL — the engine overwrites its value). The engine plants each payload value into that one slot; all arms are identical except there.

## Changes by file

### 1. Schemas — `internal/evidence/schemas/`
- `common.json`: add `$defs.injection_location` (`kind` enum query|form|json_body, `name`, `json_pointer`) and `$defs.injection` (`location` + `payloads` object of string values). Reuse `$defs.request` for `base_request`.
- `sqli.boolean_based.json`: replace `evidence.requests` + `vulnerable_parameter` with `evidence.base_request` + `evidence.injection` (payloads required: `baseline`, `true_condition`, `false_condition`). Rewrite `examples`. Keep `proof`; note the `{status, body_hash_fuzzy}` floor in `x-notes`.
- `sqli.time_based.json`: drop `$defs.delay_requests`; use `base_request` + `injection` (payloads: `control`, `delay_low`, `delay_high`). Keep `dbms_hint`, `expected_*_delay_ms`, proof. Rewrite example.
- `command_injection.time_based.json`: same transform. Leave `command_injection.oast.json` untouched.

### 2. Shared injector — `internal/validators/oast_common.go` / `ssrf_oast.go`
- Add a value-based dispatcher reused by OAST and differential validators:
  ```go
  // injectValue plants value into one declared location of req.
  func injectValue(req evidence.Request, loc InjectionLocation, value string) (evidence.Request, error)
  ```
  routing: `query` → `injectQuery`, `json_body` → `injectJSONBody`, `form` → `injectFormField` (on `req.Body`). All three already exist and already take plain string values.
- Refactor `injectOASTURL` (ssrf) and `injectSlot` (oast) to call `injectValue` for the overlapping kinds, keeping OAST-token specifics (URLHTTPS vs Domain, XML entity) layered on top — no duplicated kind switch.
- Promote one shared `InjectionLocation` struct (kind/name/json_pointer); replace the SSRF-local `ssrfInjectionLocation` with it.

### 3. `internal/validators/sqli_boolean.go`
- Replace `sqliBooleanEvidence` (three requests) with `{ BaseRequest evidence.Request; Injection injectionEvidence }`, where `injectionEvidence = { Location InjectionLocation; Payloads map[string]string }`.
- Validate: non-empty base_request; valid location; payloads has `baseline`, `true_condition`, `false_condition`; else `Invalid`.
- Build arms: `injectValue(base, loc, payloads[label])` for each label. Inject error (location absent in base_request) → `Invalid`.
- Compare floor: `dims := unionDims(ParseDimensions(proof.Compare), DimStatus, DimBodyHashFuzzy)`.
- Replay / `Fingerprint` / `Similar` / repetitions loop unchanged.

### 4. `internal/validators/timing_diff.go`
- Replace `timingEvidence.Requests.{Control,DelayLow,DelayHigh}` with `BaseRequest` + `Injection` (payloads: `control`/`delay_low`/`delay_high`).
- In `measureTimingWithClock`, build the three labeled requests once via `injectValue(base, loc, payloads[label])` before the schedule loop; time those. Randomized order, medians, control-stability, floors unchanged.
- `parseTimingEvidence`: validate base_request + injection + the three payload keys; inject errors → `Invalid`.
- `sqli_timing.go` and `command_injection.go` need no change (they delegate to the shared timing path).

### 5. Examples — rewrite fixtures, re-run to `verified`
- `examples/GHSA-ghx8-h92j-h422/evidence.json` (boolean, WeGIA): base_request POST `query_geracao_auto.php`, `kind: form`, name `query`; payloads baseline `SELECT 1 AS marker`, true `SELECT 1 AS marker WHERE 1=1`, false `... WHERE 1=2`.
- `examples/GHSA-pmf9-2rc3-vvxx/evidence.json` (sqli timing, WeGIA): base_request GET, `kind: query`, name `almox`; payloads control `1`, delay_low `0 OR (SELECT 1 FROM (SELECT SLEEP(0))x)`, delay_high `... SLEEP(5) ...`.
- `examples/GHSA-5qg5-g7c2-pfx8/evidence.json` (cmdi timing, web-check): base_request GET, `kind: query`, name `url`; payloads control `http://127.0.0.1/`, delay_low `http://127.0.0.1/?x=";sleep 0;"`, delay_high `... sleep 5 ...`.

### 6. Tests
- `sqli_boolean_test.go`, `timing_diff_test.go`: update fixtures to the new shape.
- Cheat-resistance test: a location absent from base_request → `invalid`; assert there is no evidence path that supplies a second independent request (only one slot exists).
- Compare-floor test: `compare: ["status"]` still detects a body-only difference (floor forces `body_hash_fuzzy`).

## Threshold floor

`sqli.boolean_based` always compares on `{status, body_hash_fuzzy}`, enforced in the validator (engine-owned, not schema-only) so a client cannot weaken it. Timing floors (`reps ≥ 3`, `minDelta ≥ 3000ms`) already exist in `timing_diff.go` — leave as is.

## Spec sync (alongside code)

Already updated: ADR-010, `sqli-boolean.md`, `sqli-timing.md`, `command-injection.md`, `evidence-contract.md`, `security-model.md`, `INDEX.md`.
Update during implementation (coupled to code):
- `specs/architecture/pipeline.md` mutation-authority table — add the differential injection slot as a writable position.
- `specs/domains/evidence/README.md` Core Types — if its `controls`/differential wording references the old three-request shape.

## Validation

```
go build ./...
go test ./...
golangci-lint run
# end-to-end (stand up each app first):
go run ./examples/GHSA-ghx8-h92j-h422   # boolean    -> verified
go run ./examples/GHSA-pmf9-2rc3-vvxx   # sqli timing -> verified
go run ./examples/GHSA-5qg5-g7c2-pfx8   # cmdi timing -> verified
```

## Sequencing

1. Shared `injectValue` + `InjectionLocation` refactor (no behavior change; OAST tests stay green).
2. Boolean end-to-end: schema → validator → floor → example → tests → run GHSA-ghx8 to `verified`.
3. Timing end-to-end: schema(s) → `timing_diff.go` → two examples → tests → run both to `verified`.
4. Spec sync (pipeline.md, evidence/README) + final `go test ./... && golangci-lint run`.

Convert boolean fully before timing so the pattern is proven on one type first. If a fixture cannot reach `verified` under the new shape, that is signal the shape is wrong — fix the shape, not the floor.

## Out of scope (recorded, not built)

- OAST source attribution on all-loopback (known caveat; ssrf/xxe/cmdi.oast).
- Login-recipe auth executor (keep `EvidenceHook` + authstate refs).
- Target attestation. Verdicts stay conditional on an honest target — see [security-model.md](specs/architecture/security-model.md).
