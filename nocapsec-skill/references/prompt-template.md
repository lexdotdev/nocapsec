# Operating prompt template

A nocapsec-adapted version of an offensive-PoC authoring prompt. Fill in
`{{VULNERABILITY_DESCRIPTION}}` and `{{ISOLATED_WORKSPACE_DATA}}` and run it inside an
authorized, isolated test environment. It produces a nocapsec finding the engine can
re-verify, plus a manual PoC and an explicit blindspot list.

---

Build a proof-of-concept exploit for this vulnerability on the authorized test target:
`{{VULNERABILITY_DESCRIPTION}}`.

Produce concrete, **machine-verifiable** evidence in nocapsec format whenever the
vulnerability maps to a supported validator type, and explicitly document blindspots
wherever runtime proof is partial or impossible. You are working in an isolated workspace
you are authorized to attack; all runtime commands run there.

{{ISOLATED_WORKSPACE_DATA}}

## Operating model — read before you start

nocapsec is a **proof engine, not a scanner**. It will replay your exact requests, substitute
only declared tokens (a fresh `{{nonce}}`, an allocated OAST URL), enforce a strict scope
policy, and apply **one deterministic proof rule** for the finding's `type` — returning
`verified`, `not_reproduced`, `inconclusive`, `rejected`, or `invalid`. It never improvises,
retries alternate payloads, or "fixes up" your evidence. Therefore your finding must encode
a complete, already-working exploit with precise acceptance criteria. Read
[envelope.md](envelope.md) for the shared structure, and run `nocapsec doc <type>` for your
chosen type's evidence/proof schema and example before writing JSON.

## Objectives

- Confirm the exploit actually fires against the live target before encoding it. Start with
  the **basic** technique; escalate to **advanced** (encoding tricks, filter/WAF bypasses,
  alternate vectors: query/body/header/JSON-pointer, protocol-relative or path-based
  redirect bypasses, DBMS-specific timing/boolean payloads, XML entity variants) only when
  the basic approach is blocked.
- Develop the full payload chain that demonstrates the complete scenario end to end, within
  the real application's constraints (auth, CSRF, content types, input handling).
- Map hidden parameters, undocumented endpoints, and alternate injection points relevant to
  the vulnerability.
- Where a single bug is weak alone but strong when chained (e.g. open redirect -> OAuth token
  leak, SSRF -> metadata), describe the chain even if nocapsec can only verify one link;
  verify the link(s) that map to a type and record the rest as blindspots.

## Map to exactly one validator type

| If the vulnerability is…                          | Use type | Schema |
| ------------------------------------------------- | -------- | ------ |
| Reflected/DOM XSS                                 | `xss.reflected` | `nocapsec doc xss.reflected` |
| Stored XSS                                         | `xss.stored` | `nocapsec doc xss.stored` |
| Blind XSS (out-of-band execution)                  | `xss.blind` | `nocapsec doc xss.blind` |
| Blind SQLi via timing                              | `sqli.time_based` | `nocapsec doc sqli.time_based` |
| Blind SQLi via true/false behavior                 | `sqli.boolean_based` | `nocapsec doc sqli.boolean_based` |
| Command injection via timing                        | `command_injection.time_based` | `nocapsec doc command_injection.time_based` |
| Command injection via OAST callback                 | `command_injection.oast` | `nocapsec doc command_injection.oast` |
| SSRF (server fetches a URL you control)             | `ssrf.oast` | `nocapsec doc ssrf.oast` |
| XXE (external entity fetch)                          | `xxe.oast` | `nocapsec doc xxe.oast` |
| Open redirect                                       | `open_redirect` | `nocapsec doc open_redirect` |
| Path traversal / arbitrary file read                | `path_traversal.file_read` | `nocapsec doc path_traversal.file_read` |
| IDOR / BOLA (cross-user read)                       | `idor.read` | `nocapsec doc idor.read` |

If it maps to none (CSRF, auth/business-logic bypass, deserialization RCE, race/TOCTOU,
etc.), do **not** force a type. Deliver a manual PoC and a blindspot note.

## Technical approach

- Analyze input sanitization and develop the minimal bypass that makes the payload fire;
  encode it correctly for its position (URL-encode query payloads, escape JSON bodies).
- Confirm the exploit across the vector it actually uses (GET/POST/header/JSON), and under
  the right auth context — provide credentials via the `-authstate` file, never inline.
- Prefer out-of-band/timing/blind proof where direct observation is not possible — that is
  exactly what the OAST and timing validators are for.
- Be a careful guest: keep `target` allowlists tight, prefer planted canaries over sensitive
  system files, and supply `side_effects.cleanup` to undo any state you change.

## Testing workflow

1. Use the isolated workspace for every runtime command.
2. Reproduce the exploit directly (curl / a script) until it reliably fires.
3. Save the runnable manual reproduction as `poc.py`.
4. Transcribe the confirmed exploit into `evidence.json` using the strict per-type contract:
   exact requests, `{{nonce}}`/OAST slots where `nocapsec doc <type>` dictates, and `proof`
   thresholds matching what you measured (e.g. set `min_median_delta_ms` below your real
   sleep; set `expected_message_contains` to your nonce marker).
5. Self-check the JSON: only allowed envelope keys; `target` covers every host/scheme/port
   used; no `Cookie`/`Authorization`/`Proxy-Authorization` headers; all required
   evidence/proof fields present; enum values (`accepted_signals`, `injection_location.kind`,
   `compare` dims, slot keys) spelled exactly.
6. Run `bin/nocapsec verify [capability flags] evidence.json`. Read the verdict and `policy`
   block ([runtime.md](runtime.md)). Iterate until `verified` or until the blocker is
   explicit and recorded.
7. Document all results and remaining blindspots.

## evidence_output_format

Deliver three artifacts:

1. **`evidence.json`** — a single nocapsec finding for the verifiable link of the exploit.
   It must parse and run as-is. Shape (see [envelope.md](envelope.md) and `nocapsec doc <type>`
   for the exact `evidence`/`proof` keys):

   ```json
   {
     "finding_id": "<slug>",
     "type": "<one supported type>",
     "target": {
       "expected_origin": "<scheme://host:port>",
       "allowed_hosts": ["<host>", "..."],
       "allowed_schemes": ["<scheme>"],
       "allowed_ports": [<port>]
     },
     "auth": { "required": <bool>, "auth_state_id": "<id-if-required>", "role": "<role>" },
     "evidence": { "...exact per-type fields, payloads in-place, {{nonce}}/OAST slots..." },
     "proof": { "...exact per-type acceptance thresholds..." },
     "side_effects": { "cleanup": [ "...requests that undo any state change..." ] }
   }
   ```

2. **`poc.py`** — a self-contained, runnable manual reproduction (the payload confirmed in
   step 2). Include the command(s) to run it and the expected observable effect.

3. **Blindspots note** — in plain prose:
   - exactly what the nocapsec verdict proves (the bounded claim of that type),
   - what it does **not** prove (impact beyond the proof rule, unverifiable chain links,
     human-in-the-loop steps, anything that came back `inconclusive`/`not_reproduced` and
     why),
   - the expected verdict and the capability flags needed to reproduce it
     (`-browser`/`-oast`/`-internal`/`-authstate`).

Never present `not_reproduced` or `inconclusive` as "secure", and never label an unverified
manual PoC as `verified`.
