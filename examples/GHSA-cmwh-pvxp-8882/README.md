# GHSA-cmwh-pvxp-8882

DOMPurify XSS through permanent `ALLOWED_ATTR` pollution when `setConfig()` is combined with an attribute hook. The app in `app/` uses `dompurify@3.4.10` and `jsdom`, performs the trusted render from the advisory, then reflects sanitized attacker-controlled HTML at `/render?html=...`.

Sources:

- https://github.com/cure53/DOMPurify/security/advisories/GHSA-cmwh-pvxp-8882
- https://github.com/advisories/GHSA-cmwh-pvxp-8882
- https://github.com/cure53/DOMPurify

Reproduce:

```bash
cd examples/GHSA-cmwh-pvxp-8882/app
npm install
node server.mjs
```

In another terminal from the `nocapsec` repo:

```bash
go run ./examples/GHSA-cmwh-pvxp-8882
```

The example drives Chrome to `/render?html=...`. A verified report means the vulnerable DOMPurify instance preserved an attacker-controlled `onerror` handler and Chrome observed the JavaScript dialog.
