# GHSA-8v65-47jx-7mfr

SSRF in Mailpit's `/proxy` endpoint (`CVE-2026-21859`). The advisory PoC fetches `http://127.0.0.1:8025/api/v1/info` through `/proxy?url=...`.

Sources:

- https://github.com/axllent/mailpit/security/advisories/GHSA-8v65-47jx-7mfr
- https://github.com/advisories/GHSA-8v65-47jx-7mfr
- https://github.com/axllent/mailpit/commit/3b9b470c093b3d20b7d751722c1c24f3eed2e19d

Reproduce:

```bash
git clone https://github.com/axllent/mailpit.git
cd mailpit
git checkout v1.28.0
go run . --listen 127.0.0.1:8025 --smtp 127.0.0.1:1025
```

In another terminal from the `nocapsec` repo:

```bash
nocapsec verify -internal -oast examples/ssrf-oast-mailpit/evidence.json
```

The example starts an embedded OAST receiver and replaces the `url` query parameter with that callback URL. A verified report means Mailpit fetched it server-side via `/proxy`.
