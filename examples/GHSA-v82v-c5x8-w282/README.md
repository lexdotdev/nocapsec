# GHSA-v82v-c5x8-w282

Stored XSS in [NiceGUI](https://github.com/zauberzeug/nicegui) `<= 3.6.1`
(`CVE-2026-25516`). `ui.markdown()` renders user-supplied markdown via
`markdown2.markdown()` with no safe mode:

```python
# nicegui/elements/markdown.py  (prepare_content)
html = markdown2.markdown(content, extras=[...])   # no sanitization
```

Embedded raw HTML (e.g. `<img src=x onerror=...>`) passes through unchanged and is
bound to the client element's `innerHTML`, so any app that stores untrusted text and
later renders it with `ui.markdown()` has persistent XSS that fires automatically on
page render. Fixed in `3.7.0` (DOMPurify, `sanitize=True` default).

The app in `app/` installs the **real pinned vulnerable `nicegui==3.6.1`** and exposes
the exact vulnerable path: `POST /store` persists a note, `GET /note` renders it with
`ui.markdown()`.

Sources:

- https://github.com/zauberzeug/nicegui/security/advisories/GHSA-v82v-c5x8-w282
- https://github.com/advisories/GHSA-v82v-c5x8-w282

## Reproduce

```bash
cd examples/GHSA-v82v-c5x8-w282/app
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # nicegui==3.6.1
.venv/bin/python harness.py        # serves http://127.0.0.1:8088
```

In another terminal from the `nocapsec` repo (a real Chrome/Chromium is required):

```bash
export NOCAPSEC_CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
go run ./examples/GHSA-v82v-c5x8-w282
```

The example first replays the `POST /store` that persists the payload, then drives a
fresh Chrome context to `GET /note`. NiceGUI delivers the markdown HTML through its
Vue initial-state as an entity-encoded `innerHTML` prop; the browser decodes it into a
live `<img src=x onerror=...>` node whose failed image load fires `onerror`
immediately — no user interaction. A verified report (`signal: javascript_dialog`,
nonce matched, execution origin `http://127.0.0.1:8088`) proves the stored payload
executed. A plain `curl` of `/note` will **not** fire it — the proof needs a real
JS-executing browser.
