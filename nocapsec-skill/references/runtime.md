# Runtime: auth, capabilities, CLI, verdicts, blindspots

How to actually run a finding, give it credentials, read the result, and write up what was
not provable.

## Running a finding

```sh
# one-shot: verify a single finding and print the JSON report
bin/nocapsec verify [flags] evidence.json

# long-running HTTP API + worker pools (same flags)
bin/nocapsec serve [flags]
```

### Capability flags

A validator needs the right capability enabled or it returns `inconclusive` (missing
capability). Enable only what the type requires:

| Flag                        | Enables | Needed by |
| --------------------------- | ------- | --------- |
| `-browser`                  | headless Chrome runner | `xss.reflected`, `xss.stored`, `open_redirect` |
| `-chrome-path <path>`       | explicit browser binary (else auto-detect / `NOCAPSEC_CHROME_PATH`) | with `-browser` if detection fails |
| `-oast`                     | embedded OAST receiver | `xss.blind`, `ssrf.oast`, `xxe.oast`, `command_injection.oast` |
| `-oast-domain <suffix>`     | OAST callback domain (default `oast.test`) | tune OAST |
| `-oast-advertise-host <ip>` | host advertised in OAST callbacks/DNS (default `127.0.0.1`) | tune OAST |
| `-authstate <file>`         | encrypted in-memory auth store | `idor.read`, authenticated `xss.stored`, any `auth.required` finding |
| `-internal`                 | allow loopback/private IP ranges | targets on `127.0.0.1`/`10.x`/`192.168.x` |

Timing validators (`sqli.time_based`, `sqli.boolean_based`, `command_injection.time_based`)
need no special flag — plain HTTP.

Example for a local blind-SSRF finding against `127.0.0.1`:

```sh
bin/nocapsec verify -oast -internal evidence.json
```

## Auth-state file (`-authstate`)

A JSON **array** of `{ state, credentials }` entries. Credentials never go in the finding —
the finding only references a state by `auth_state_id`.

```json
[
  {
    "state": {
      "id": "user-session",
      "kind": "http_cookie_jar",
      "allowed_origins": ["https://app.example.com"],
      "role": "user",
      "healthcheck": {
        "method": "GET",
        "url": "https://app.example.com/api/me",
        "expected_status": 200,
        "expected_body_contains": "\"email\""
      }
    },
    "credentials": {
      "cookies": [
        { "name": "session", "value": "<cookie-value>", "domain": "app.example.com", "path": "/" }
      ],
      "headers": { "x-csrf-token": "<token>" }
    }
  }
]
```

- `state.id` must be unique across the file and match the finding's `auth_state_id`.
- `allowed_origins` pins where the credential may be sent.
- `healthcheck` is stored metadata today; the current engine checks expiry/not-found states
  but does not execute a live healthcheck request yet.
- **For `idor.read`**, the HTTP-replay path applies the credential **`headers`** map to the
  request (e.g. put the session in a `cookie` or `authorization` header there). Provide a
  separate entry for the owner and the attacker, with **different** ids.
- Browser validators carry `auth_state_id`; full browser storage injection is not wired yet.

## Reading the report

`verify` prints one JSON object:

```json
{
  "finding_id": "reflected-xss-search",
  "type": "xss.reflected",
  "verdict": "verified",
  "target_origin": "http://127.0.0.1:3000",
  "proof": { "...type-specific proof block..." },
  "policy": {
    "scheme_ok": true,
    "initial_origin_pinned": true,
    "final_origin_ok": true,
    "redirects": []
  },
  "artifacts": { "...screenshots / captures when applicable..." },
  "decided_at": "2026-06-19T12:00:00Z",
  "reason": "only set for invalid/rejected/inconclusive"
}
```

### Verdicts → what to do next

| Verdict          | Meaning | Action |
| ---------------- | ------- | ------ |
| `verified`       | The deterministic proof rule passed. | Done — this is real, reproducible evidence. |
| `not_reproduced` | The validator ran fully but ≥1 proof condition failed. | The exploit did not fire as described. Re-check the payload against the live target; tighten/fix the request; reconsider whether it is exploitable. A true negative is a valid result. |
| `inconclusive`   | Timeout, missing capability, unstable control, auth expiry, backend unavailable. | Fix the runtime (enable the flag, refresh auth, raise timeout/window, stabilize) and re-run. Not a statement about the vuln. |
| `rejected`       | Policy blocked a URL: out-of-scope host/scheme/port, bad origin, unsafe redirect, blocked IP. | Fix `target` allowlist / origins, or add `-internal` for loopback. The `policy` block and `reason` say which check failed. |
| `invalid`        | The finding JSON was malformed/incomplete/strict-schema violation/dangling slot. | Fix the JSON. `reason` codes include `unknown_field`, `missing_field`, `wrong_type`, `prose_only`, `inlined_credential`, `bad_request`, `bad_url`, `dangling_mutation_slot`, `unknown_type`. |

The `policy` block (`scheme_ok`, `initial_origin_pinned`, `final_origin_ok`, `redirects`)
is filled for browser/redirect findings and is the first place to look on a `rejected`.

## Documenting blindspots

nocapsec proves a specific, bounded claim per type. Always state plainly what it did **not**
establish. Treat these as blindspots and write them next to the finding:

- **Unsupported class.** The vulnerability does not map to any supported type (e.g. CSRF,
  business-logic, auth bypass via logic, deserialization RCE, race/TOCTOU, DoS, stored
  secrets). Deliver a manual `poc.py` and say nocapsec cannot verify it.
- **Out-of-band only / human-in-the-loop.** Execution requires an admin to open a page, a
  delayed job, or interaction past the poll window — note it and, for blind XSS, widen
  `poll_window_seconds`; if still past the window the result is `not_reproduced`, not proof
  of safety.
- **Impact beyond the proof rule.** The validator proves *read* (IDOR read, file read) or
  *callback* (SSRF/XXE/cmdi OAST) or *execution signal* (XSS) — not write, not full RCE, not
  data exfiltration volume. If real impact is larger, the finding under-states it; say so.
- **Scope/reachability.** A target you could not reach, an origin you could not pin, or a
  control you could not stabilize → `inconclusive`. That is a gap in evidence, not a clean
  bill of health.

Never present `not_reproduced` or `inconclusive` as "secure", and never present an
unverified manual PoC as `verified`.
