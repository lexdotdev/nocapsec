# GHSA-2877-693q-pj33

Unauthenticated OS command injection in [GenieACS](https://github.com/genieacs/genieacs)
`>= 1.2.0, < 1.2.8` (`CVE-2021-46704`). The UI API's ping endpoint passes the
user-supplied host straight into a shell command:

```ts
// lib/ping.ts
cmd = `ping -w 1 -i 0.2 -c 3 ${host}`;   // host interpolated into the shell string
exec(cmd, (err, stdout) => { ... });     // child_process.exec -> /bin/sh
// lib/ui/api.ts
router.get("/ping/:host", async (ctx) => { ping(ctx.params.host, ...); });  // no auth check
```

The `host` reaches `child_process.exec` unsanitized, so the server resolves and pings
an attacker-named host (and runs injected shell commands). Fixed in `1.2.8`.

The app in `app/` is a faithful reproduction of that sink: it execs `ping -c 1
${host}` with the host taken from the request. GenieACS exposes the sink via a GET
path parameter and uses Linux-only `ping` flags; this harness exposes the identical
`exec(\`ping ... ${host}\`)` construction over `POST /ping` (form field `host`) so the
engine's body-field injection applies, and uses `-c 1` so it runs on macOS/BSD too.

This is **command_injection.oast**: the proof is out-of-band. The engine writes its
OAST callback host (`<id>.oast.test`) into the `host` field; the server's `ping`
performs a DNS lookup of it, and that lookup landing on the receiver — from loopback,
so it is attributed to the target — is the proof.

Sources:

- https://github.com/advisories/GHSA-2877-693q-pj33
- https://security.snyk.io/vuln/SNYK-JS-GENIEACS-2419025

## Reproduce

The engine's OAST DNS receiver listens on a fixed loopback port (`127.0.0.1:15353`,
set via `-oast-dns-addr`). On macOS, route the `oast.test` zone to it once via a resolver
file (this is the one privileged step — the receiver itself is unprivileged):

```bash
printf 'nameserver 127.0.0.1\nport 15353\n' | sudo tee /etc/resolver/oast.test
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```

Start the app:

```bash
cd examples/command-injection-oast-genieacs/app
node server.js              # serves http://127.0.0.1:8095
```

In another terminal from the `nocapsec` repo:

```bash
nocapsec verify -internal -oast -oast-dns-addr 127.0.0.1:15353 \
  examples/command-injection-oast-genieacs/evidence.json
```

The engine starts its OAST receiver (DNS on `127.0.0.1:15353`), writes
`<id>.oast.test` into the `host` field, posts it to `/ping`, and waits for the DNS
callback. A verified report (`protocol: dns`, `attributed_to: target_infra`) proves
the injected host reached the OS resolver through the `ping` command.

> Linux note: `/etc/resolver` is macOS-specific. On Linux, run the app and the engine
> inside a container started with `--dns 127.0.0.1` and the receiver on `:53`, so the
> container's resolver forwards lookups to the receiver on loopback.
