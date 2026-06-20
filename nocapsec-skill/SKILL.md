---
name: nocapsec-exploit
description: Compose a proof-of-concept exploit for a given vulnerability in an authorized test target and emit it as a nocapsec finding (evidence.json) that the engine can deterministically re-verify. Use when asked to build a PoC, write an exploit, or produce nocapsec evidence/finding JSON for a vulnerability (XSS, SQLi, SSRF, XXE, command injection, open redirect, path traversal, IDOR). Maps the bug to exactly one nocapsec validator type, fills the strict evidence/proof contract, and documents blindspots when runtime proof is not fully achievable.
---

# nocapsec exploit authoring

Turn a described vulnerability, on an **authorized** test target, into a self-contained
reproduction that the nocapsec proof engine can replay and judge.

nocapsec is **not a scanner**. It never improvises payloads, never discovers issues, and
never "fixes up" your evidence. It does exactly one thing per finding:

1. parse your finding JSON against a **strict** schema (unknown keys → `invalid`),
2. enforce policy (origin pinning, host/scheme/port allowlist, SSRF guards),
3. replay your **exact** requests, substituting only declared tokens (a fresh `{{nonce}}`,
   an allocated OAST URL), and
4. apply **one deterministic proof rule** for the finding's `type`, returning a verdict:
   `verified`, `not_reproduced`, `inconclusive`, `rejected`, or `invalid`.

Your job is to author a finding precise enough that the proof rule fires. If you write a
loose payload, a wrong field name, or aim at the wrong validator, you get `invalid` /
`not_reproduced` — not a "best effort" pass. Precision is the whole game.

## When to use

Use this skill when the task is "build a PoC / write an exploit / produce a nocapsec
finding" for a concrete vulnerability on a target you are authorized to test (pentest
engagement, CTF, security research, your own app in an isolated workspace).

If the vulnerability does **not** map to one of the 12 supported types (below), nocapsec
cannot verify it. Still produce a manual PoC (`poc.py`) and record it as a **blindspot** —
do not force a mismatched `type`.

## Supported validator types

Each `type` has its own strict evidence/proof contract. Run **`nocapsec doc <type>`** for the
full **JSON Schema** (draft 2020-12) **and a runnable example** before writing the JSON —
field names and enum values must be exact. The printed schema is the exact document the
engine validates against, so it never drifts from what the parser enforces (the static `.md`
specs in `specs/` have drifted; trust the CLI).

| `type`                          | Class                       | Needs            | Schema |
| ------------------------------- | --------------------------- | ---------------- | ------ |
| `xss.reflected`                 | Reflected / DOM XSS         | `-browser`       | `nocapsec doc xss.reflected` |
| `xss.stored`                    | Stored XSS                  | `-browser` `-authstate` | `nocapsec doc xss.stored` |
| `xss.blind`                     | Blind XSS (OAST)            | `-oast`          | `nocapsec doc xss.blind` |
| `sqli.time_based`               | Time-based blind SQLi       | (timing)         | `nocapsec doc sqli.time_based` |
| `sqli.boolean_based`            | Boolean blind SQLi          | (http)           | `nocapsec doc sqli.boolean_based` |
| `command_injection.time_based`  | Time-based command injection| (timing)         | `nocapsec doc command_injection.time_based` |
| `command_injection.oast`        | OAST command injection      | `-oast`          | `nocapsec doc command_injection.oast` |
| `ssrf.oast`                     | SSRF (OAST callback)        | `-oast` `-internal`* | `nocapsec doc ssrf.oast` |
| `xxe.oast`                      | XXE (OAST callback)         | `-oast`          | `nocapsec doc xxe.oast` |
| `open_redirect`                 | Open redirect               | `-browser`       | `nocapsec doc open_redirect` |
| `path_traversal.file_read`      | Path traversal / LFI read   | (http)           | `nocapsec doc path_traversal.file_read` |
| `idor.read`                     | IDOR / BOLA read            | `-authstate`     | `nocapsec doc idor.read` |

\* `-internal` only when the target origin is loopback/private (e.g. `127.0.0.1`).

`nocapsec doc` with no argument lists every finding type. Pass a full type id from the table.

Shared structure every finding uses (envelope, target, auth, request object, mutation
tokens, the strict-schema rules) is in **[references/envelope.md](references/envelope.md)** —
read it first. Runtime concerns (auth-state file, CLI flags/capabilities, reading the
verdict, blindspots) are in **[references/runtime.md](references/runtime.md)**.

## Cardinal rules (these cause `invalid` / silent failure)

- **Strict keys.** Envelope, `target`, `evidence`, and `proof` reject unknown keys. Copy
  field names verbatim from `nocapsec doc <type>`. No extra fields, no comments in the JSON.
- **One type, one rule.** Pick the single best-fit `type`. nocapsec will not try variants.
- **No improvisation budget.** The engine replays your request bytes as-is. Put the full,
  working payload in the request — the engine will not escalate, retry alternates, or
  change host/method/parameter/role.
- **Tokens, not guesses.** Use the literal token `{{nonce}}` where the proof must observe a
  unique value (XSS message, redirect final URL, IDOR marker). The engine generates the
  value at run time; the proof checks the observed signal contains it. Do not hardcode a
  "random" string — it will not match.
- **Credentials are referenced, never inlined.** Any `Cookie`, `Authorization`, or
  `Proxy-Authorization` header in a request → `invalid` (`inlined_credential`). Auth comes
  from an `auth_state_id` plus an `-authstate` file (see [references/runtime.md](references/runtime.md)).
- **Policy is a hard wall.** Every URL in the finding must satisfy `target` allowlists and
  origin pinning. Out-of-scope host/scheme/port → `rejected`. The `target` allowlist is the
  sandbox; keep it tight and accurate.

## Workflow

1. **Classify.** Map the vulnerability to exactly one supported `type`. If none fits, go to
   step 7 (blindspot-only) and still deliver a manual PoC.
2. **Get the schema:** run `nocapsec doc <type>` for the type's evidence/proof contract and
   example, and read [references/envelope.md](references/envelope.md) for the shared structure.
3. **Build the working payload first.** In the isolated workspace, confirm the exploit
   actually fires with `curl`/a script against the live target — basic technique first,
   then escalate (encoding, filter bypass, alternate vector) only as needed. You cannot
   author a correct finding for a payload you have not seen work.
4. **Author `evidence.json`.** Transcribe the confirmed request(s) into the strict
   contract: exact method/URL/headers/body, `{{nonce}}`/OAST slots where `nocapsec doc
   <type>` says, and `proof` thresholds that match what you observed.
5. **Self-verify the JSON shape.** Confirm: only allowed envelope keys; `target` allowlist
   covers every host/scheme/port you use; no inlined credential headers; required
   evidence/proof fields all present; enum values (signals, kinds, compare dims) spelled
   exactly as `nocapsec doc <type>` lists them.
6. **Run it** (when the runtime is available): `bin/nocapsec verify [flags] evidence.json`
   with the capability flags from the table. Read the verdict and `policy` block per
   [references/runtime.md](references/runtime.md). Iterate until `verified` or until the
   remaining blocker is explicit.
7. **Document blindspots.** Anything not provable by nocapsec — unsupported class, a step
   that needs human interaction, a signal outside the proof rule, a target you could not
   reach — gets written down plainly. Never present an unverified claim as verified.

## Deliverables

- `evidence.json` — the nocapsec finding (one per vulnerability).
- `poc.py` — a runnable manual reproduction (the payload you confirmed in step 3).
- A short **blindspots** note — what nocapsec proves here, and what it does not.

## Operating prompt

A ready-to-use, nocapsec-adapted version of the offensive-PoC prompt lives in
**[references/prompt-template.md](references/prompt-template.md)**. Use it (filling in the
vulnerability description and workspace data) when you want the full authoring procedure as
a single instruction block.
