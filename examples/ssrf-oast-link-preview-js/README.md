# GHSA-4gp8-rjrq-ch6q

Server-Side Request Forgery in [`link-preview-js`](https://github.com/OP-Engineering/link-preview-js)
`<= 4.0.0` (`CVE-2026-43897`). `getLinkPreview(text)` extracts the first URL from
attacker-controlled text and `fetch()`es it server-side to build an OpenGraph
preview. In 4.0.0 the loopback/DNS guard is gated behind `if (!!!options.resolveDNSHost)`
and is therefore **skipped by default**, so the server issues an unconditional
outbound GET to the supplied URL. Fixed in `4.0.1`.

This is the canonical **blind** outbound-fetch primitive: a stored, attacker-supplied
link (chat message, profile, CMS unfurl) is fetched out-of-band by the server, and
the only observable signal is the callback itself.

The app in `app/` installs the **real pinned vulnerable `link-preview-js@4.0.0`** and
exposes the exact vulnerable call at `GET /preview?url=...`.

Sources:

- https://github.com/advisories/GHSA-4gp8-rjrq-ch6q
- https://github.com/OP-Engineering/link-preview-js

## Reproduce

```bash
cd examples/ssrf-oast-link-preview-js/app
npm install            # pulls link-preview-js@4.0.0
PORT=8099 node server.js
```

In another terminal from the `nocapsec` repo:

```bash
nocapsec verify -internal -oast -oast-callback-host oast.localtest.me \
  examples/ssrf-oast-link-preview-js/evidence.json
```

### The `localtest.me` detail

The advisory's own SSRF regex **rejects raw-IP and `localhost` URLs** but accepts any
TLD'd hostname — that is precisely the bug (a hostname that *resolves* to an internal
address is fetched anyway). nocapsec's embedded OAST receiver normally hands out a
raw-IP callback (`http://127.0.0.1:port/...`), which `link-preview-js` would refuse.
So the example points the receiver's callback host at `oast.localtest.me`, a name that
resolves to `127.0.0.1` via public DNS (`SetCallbackHost`). The library accepts the
hostname, resolves it to loopback, and fetches the local receiver — a faithful
reproduction of fronting an internal target with a benign-looking domain.

A verified report (`protocol: http`, `attributed_to: target_infra`) proves the
server performed the out-of-band fetch. Requires outbound DNS for `*.localtest.me`.
