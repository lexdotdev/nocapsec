## How It Works

nocapsec runs each finding through one fixed pipeline and returns a single terminal verdict. Every stage fails closed: a finding is `verified` only when the selected proof rule is satisfied, never by default.

### The pipeline

1. **Parse evidence.** Reject empty or malformed JSON, unknown finding types, inlined credentials, schema violations, bad URLs, and dangling mutation slots. Failure returns `invalid`.
2. **Gate on policy.** Build an enforcer from the target's allowed schemes, hosts, ports, and expected origin, then check every evidence URL before execution. DNS/IP policy blocks unsafe ranges unless `-internal` enables an internal assessment. A policy failure returns `rejected`.
3. **Check auth.** If the finding requires `auth_state_id` and an auth store is configured with `-authstate`, load that state. Missing or expired state returns `inconclusive`.
4. **Plan the proof.** Look up exactly one validator by `type` and mint a fresh per-run nonce. Missing validators return `invalid`.
5. **Dispatch.** Run the validator on the bounded pool for its capability: `http-replay`, `timing`, `browser`, or `oast`.
6. **Run the proof rule.** The validator replays the supplied evidence, injects only declared mutation slots, and checks the deterministic signal for that finding type. It returns `verified`, `not_reproduced`, `rejected`, `invalid`, or `inconclusive`.
7. **Stamp and return.** Map the validator result to a `Report`, attach artifact refs collected by the run, and record the decision time.

### Finding types

The current engine registers these proof types:

- HTTP replay: `path_traversal.file_read`, `idor.read`, `nosqli.auth_bypass`, `sqli.boolean_based`, `sqli.inband`, `sqli.union_extract`, `ssti.reflected`, `ssti.stored`, `crlf.response_splitting`, `cache_poisoning.canary`
- Timing: `sqli.time_based`, `command_injection.time_based`
- Browser: `xss.reflected`, `xss.stored`, `open_redirect`
- OAST: `ssrf.oast`, `xxe.oast`, `command_injection.oast`, `xss.blind`

### OAST (out-of-band proof)

Some bugs are blind: the response body reveals nothing, and the proof is the target reaching out to a callback controlled by nocapsec. OAST allocates a unique correlation ID with HTTP and DNS endpoints, plants the callback value into the declared mutation slot, replays the request, and polls for an interaction.

- Enable the embedded receiver with `-oast`. It starts local HTTP and DNS listeners. Use `-oast-http-addr`, `-oast-dns-addr`, `-oast-domain`, and `-oast-advertise-host` when the target must reach a specific host.
- `ssrf.oast`, `xxe.oast`, and `command_injection.oast` require the callback source to look like target infrastructure, not the verifier. On all-loopback setups that attribution is weaker by design.
- `xss.blind` is an OAST validator, not a browser validator. It injects a callback into the blind payload and waits for the out-of-band hit.
- Credential headers such as `Cookie`, `Authorization`, and `Proxy-Authorization` are rejected before execution.

### Browser (client-side proof)

Some bugs only fire when a real browser parses and executes a response. The engine drives a fresh headless Chromium profile over the Chrome DevTools Protocol, navigates to the entrypoint, waits for the declared mode, runs bounded post-load actions, and records navigation, JavaScript dialog, console, and network events.

- Enable this path with `-browser`; the rest of the engine can run without Chrome or Chromium.
- Used by `xss.reflected`, `xss.stored`, and `open_redirect`. Without a browser, those return `inconclusive`.
- XSS proof requires an accepted signal from the target origin carrying the per-run nonce. Signals from verifier instrumentation do not count.
- Open redirect proof requires a target-origin start, a declared external final origin, a final URL carrying the nonce, and a committed target-to-external transition.
- On proof, the runner attempts to capture a screenshot and DOM snapshot through the artifact store.
