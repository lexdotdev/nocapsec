# nocapsec

> No cap. Just verified vulnerabilities.

Proof engine for security findings. A client (typically an LLM) proposes a vulnerability finding as a structured reproduction bundle; the engine validates the evidence, applies strict policy, executes one deterministic proof rule, and returns a reproducible verdict (`verified`, `not_reproduced`, `inconclusive`, `rejected`, `invalid`). It is not a scanner: it never improvises payloads and never discovers issues on its own.

## How It Works

nocapsec runs each finding through one fixed pipeline and returns a single terminal verdict. Every stage fails closed — a finding is `verified` only when a proof rule is satisfied, never by default.

### The pipeline

1. **Parse evidence.** Reject malformed/empty input and inlined credentials, confirm the finding type is known, validate against its JSON schema, canonicalize URLs/hosts, and check mutation slots. Failure -> `invalid`.
2. **Gate on policy.** Build an enforcer from the target's allowed schemes, hosts, ports, and origin, then check every URL: allowlists, origin pinning, and DNS-resolved IP blocking (loopback, private, link-local, cloud-metadata). A violation -> `rejected`, before any request leaves the process. `-internal` relaxes IP blocking for internal targets.
3. **Check auth.** If the finding requires it, load the referenced auth state. Missing or expired -> `inconclusive`.
4. **Look up the validator.** Each finding type maps to exactly one deterministic validator. None -> `invalid`.
5. **Dispatch.** Mint a fresh random nonce and dispatch on a bounded pool by capability (`http-replay`, `timing`, `browser`, `oast`) with per-capability, per-target concurrency limits.
6. **Run the proof rule.** The validator runs its one deterministic check — replaying requests through the policy-pinned client (policy re-checked on every redirect hop) or driving the browser, matching the nonce to prove fresh execution. Result: `verified`, `not_reproduced`, `rejected`, `invalid`, or `inconclusive`.
7. **Stamp and return.** Map the result to a `Report`, attach artifacts (evidence, HTTP exchanges, screenshots), and record the decision time.

### OAST (out-of-band proof)

Some bugs are blind — the response body reveals nothing, and the only proof is the target reaching *out* to a server we control. OAST allocates a unique callback (a correlation ID with DNS/HTTP endpoints), plants it into the declared injection slot, replays the request, and polls for an interaction. To stop the engine from proving itself, it attributes the callback's source to the target's infrastructure and drops anything that looks like the verifier or background noise (it can't discriminate when everything is loopback).

- Backed by an embedded in-process receiver (its own HTTP + DNS listeners) or a self-hosted Interactsh server.
- Opt-in via `-oast`. Used by `ssrf.oast`, `xxe.oast`, `command_injection.oast` (attribution required), and `xss.blind` (attribution relaxed). `xss.blind` is an OAST validator, not a browser one: it injects a callback into the blind payload and waits for the out-of-band hit.

### Browser (client-side proof)

Some bugs only fire when a real browser parses and executes a response — HTTP replay can't see them. The engine drives a throwaway headless Chromium over the Chrome DevTools Protocol, navigates to the entrypoint, waits for load/network-idle, and watches CDP events (navigations, JS dialogs, console, network). A signal counts only if it fires from the target origin and carries the per-run nonce; on proof it captures a screenshot and DOM snapshot. `xss.reflected` may also run a bounded set of post-load actions (clicks and waits — never arbitrary script).

- Opt-in via `-browser`; the rest of the engine needs no browser.
- Used by `xss.reflected`, `xss.stored`, and `open_redirect`. Without a browser, those return `inconclusive`.

## Installation

### Prerequisites

- **Go 1.26.1 or newer** — to build the binary.
- **Chrome or Chromium** — only for browser-backed validators (reflected/stored XSS, open redirect). The rest of the engine runs without a browser.

### Build

```sh
git clone https://github.com/lexdotdev/nocapsec.git
cd nocapsec
go build -o bin/nocapsec ./cmd/nocapsec
```

Or install straight onto your `PATH`:

```sh
go install github.com/lexdotdev/nocapsec/cmd/nocapsec@latest
```

Verify the build:

```sh
./bin/nocapsec verify path/to/finding.json   # one-shot verification
./bin/nocapsec serve                         # HTTP API + worker pools
./bin/nocapsec doc ssrf.oast                 # print the schema + example for a finding type
```

## Using With An LLM

- See [llms.txt](llms.txt) for an LLM-oriented guide to the CLI, HTTP API, evidence rules, and common finding shapes.
- See [nocapsec skill](nocapsec-skill/SKILL.md) for example of exploiter agent that produces evidence in nocapsec format.

### Chrome / Chromium

Install a browser only if you use the browser-backed validators. Pass `-browser` to enable the runner.

- **macOS** — `brew install --cask google-chrome` (or `chromium`), or download Chrome from google.com/chrome.
- **Debian / Ubuntu** — `sudo apt-get install -y chromium` (or `chromium-browser`).
- **Fedora / RHEL** — `sudo dnf install -y chromium`.
- **Docker / CI** — use a base image that bundles Chromium (e.g. `chromedp/headless-shell`) and point the engine at it (see below).

The binary is located automatically in this precedence order:

1. the `-chrome-path` flag (explicit path),
2. the `NOCAPSEC_CHROME_PATH` environment variable,
3. a `google-chrome` / `chromium` command on `PATH`,
4. a well-known install location for the host OS (macOS app bundles, `/usr/bin`, `/snap/bin`, Windows `Program Files`).

On macOS, Chrome installs under `/Applications` and is not on `PATH`; detection covers the standard, Beta, and Canary bundles as well as per-user installs under `~/Applications`. When detection fails, pin the binary explicitly:

```sh
nocapsec serve -browser -chrome-path "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
# or, equivalently:
NOCAPSEC_CHROME_PATH="/path/to/chrome" nocapsec serve -browser
```
