# nocapsec

> No cap. Just verified vulnerabilities.

Proof engine for security findings. A client (typically an LLM) proposes a vulnerability finding as a structured reproduction bundle; the engine validates the evidence, applies strict policy, executes one deterministic proof rule, and returns a reproducible verdict (`verified`, `not_reproduced`, `inconclusive`, `rejected`, `invalid`). It is not a scanner: it never improvises payloads and never discovers issues on its own.

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
