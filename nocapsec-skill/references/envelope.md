# Finding envelope (shared by every type)

Every nocapsec finding is a single JSON object with this top-level shape. The envelope and
the `target` object are **strict**: any key not listed here is rejected with `invalid`
(`unknown_field`). Per-type `evidence` and `proof` are strict too — see the type's reference.

```json
{
  "finding_id": "unique-id",
  "type": "xss.reflected",
  "target": {
    "expected_origin": "http://127.0.0.1:3000",
    "allowed_hosts": ["127.0.0.1"],
    "allowed_schemes": ["http"],
    "allowed_ports": [3000]
  },
  "auth": { "required": false },
  "evidence": { },
  "proof": { },
  "controls": [],
  "mutation_slots": { },
  "side_effects": { "cleanup": [] }
}
```

## Top-level keys

| Key              | Required | Notes |
| ---------------- | -------- | ----- |
| `finding_id`     | yes      | Non-empty string, unique per finding. |
| `type`           | yes      | Exactly one supported validator type. |
| `target`         | yes      | Scope/policy object (below). |
| `evidence`       | yes      | Non-empty object; type-specific; strict keys. A prose string or `{}` → `invalid` (`prose_only`). |
| `proof`          | yes      | Type-specific object; strict keys; the deterministic acceptance criteria. |
| `auth`           | no       | Auth reference (below). Omit or `{"required": false}` for unauthenticated findings. |
| `controls`       | no       | Array of request objects, for differential validators that take them. |
| `mutation_slots` | no       | Optional top-level slot declarations (see "Tokens & slots"). Most types do not need this at the top level. |
| `side_effects`   | no       | `{ "cleanup": [ <request>, ... ] }`. Cleanup requests run after a state-changing finding, regardless of verdict. |

There is **no** `scope_id` and **no** `state_changing` field — do not add them.

## `target` — the policy sandbox

`target` bounds everything the engine is allowed to touch. Every URL in the finding is
checked against it; anything out of scope is `rejected` (not a soft failure).

| Field            | Required | Meaning |
| ---------------- | -------- | ------- |
| `expected_origin`| yes      | The origin the finding is pinned to, e.g. `https://app.example.com`. Used for origin pinning. |
| `allowed_hosts`  | yes      | Non-empty array of hostnames the engine may contact. |
| `allowed_schemes`| yes      | Non-empty array, e.g. `["https"]` or `["http"]`. |
| `allowed_ports`  | no       | Array of ints, e.g. `[443]`. Omit to allow scheme defaults. |

Keep the allowlist as tight as the exploit needs. If your payload reaches a second host
(e.g. an attacker callback host for open redirect), that host/port must also be listed, or
the request is `rejected`.

For loopback/private targets (`127.0.0.1`, `10.x`, `192.168.x`, etc.) you must also pass the
`-internal` flag at run time, or policy blocks the request as an SSRF guard. See
[runtime.md](runtime.md).

## `auth` — referenced, never inlined

```json
"auth": { "required": true, "auth_state_id": "user-session", "role": "user" }
```

Only these three keys are allowed (`required`, `auth_state_id`, `role`); anything else →
`invalid` (`inlined_credential`). When `required` is true, `auth_state_id` must be present
and must match an entry in the `-authstate` file. Raw cookies/tokens never appear in the
finding — they live in the auth-state file (see [runtime.md](runtime.md)).

## The request object

Wherever a field expects a request (`entrypoint`, `request`, `setup_resource`,
`negative_control`, `requests.control`, cleanup steps, ...) it has this shape:

```json
{
  "method": "POST",
  "url": "https://app.example.com/path?x=1",
  "headers": [ { "name": "content-type", "value": "application/json" } ],
  "body": "{\"q\":\"value\"}"
}
```

- `method` and `url` are required and non-empty.
- `headers` is an array of `{name, value}` objects (omit if none).
- `body` is the **raw wire body** as a string. For a JSON body, it is a JSON string (escape
  the inner quotes), not a nested object.
- **Never** include `Cookie`, `Authorization`, or `Proxy-Authorization` headers — that is an
  instant `invalid` (`inlined_credential`). Use `auth` + the auth-state file instead.

## Tokens & slots — how the engine injects values

The engine substitutes only a small, declared set of values; it changes nothing else.

- **`{{nonce}}` (built-in).** Place the literal token `{{nonce}}` anywhere in a request URL
  or body (and in proof match fields like `expected_message_contains`). At run time the
  engine generates one fresh random nonce per finding and replaces every `{{nonce}}` (and
  its URL-encoded forms `%7B%7Bnonce%7D%7D`) with it. The proof rule then requires the
  observed signal to contain that nonce. This is how XSS, open redirect, and IDOR tie an
  observed effect back to *your* injection. Do not hardcode a random literal — it cannot
  match the run-time value.
- **`{{created_resource_id}}` (built-in, IDOR only).** In `idor.read`, the engine creates a
  resource as the owner, extracts its id, and substitutes `{{created_resource_id}}` in the
  attacker's `attack_request` URL. See `nocapsec doc idor.read`.
- **OAST slots (inside `evidence`).** For `xss.blind`, `xxe.oast`, and
  `command_injection.oast`, the evidence carries its own `mutation_slots` object mapping a
  fixed slot key to the position the OAST value is written into. The engine allocates a
  unique OAST URL/host and writes it there. The slot key and value grammar are type-specific
  — see `nocapsec doc xss.blind`, `nocapsec doc xxe.oast`, and `nocapsec doc command_injection.oast`.
  (`ssrf.oast` is different again — it uses `injection_location`, not `mutation_slots`.)
- **Top-level `mutation_slots`.** Optional. When present, each value must resolve to a real
  position in the finding's requests, using this grammar: `query:<param>`, `header:<name>`,
  `body:<token>`, an RFC-6901 JSON pointer `/a/b`, or a bare token (matched literally or as
  `{{token}}`). A slot that points nowhere → `invalid` (`dangling_mutation_slot`). Most
  findings rely on the built-in `{{nonce}}` token and the per-type OAST slots instead, and
  omit this.

## Verdicts (what you are aiming for)

`verified` · `not_reproduced` · `inconclusive` · `rejected` · `invalid`. The proof rule
returns `verified` only when **all** of its numbered conditions hold. See [runtime.md](runtime.md)
for how to read the full report and map each verdict to a next action.
