"""Thin harness around the REAL pinned vulnerable nicegui==3.6.1 ui.markdown().

POST /store {"content": "..."} persists an attacker note server-side.
GET  /note  renders it with ui.markdown(), whose prepare_content() calls
markdown2.markdown() with no safe_mode/sanitization (nicegui/elements/markdown.py),
so raw HTML in the note is bound to the client element's innerHTML and executes on
render -- stored XSS (GHSA-v82v-c5x8-w282 / CVE-2026-25516). Fixed in 3.7.0, which
adds DOMPurify with sanitize=True by default.

Run (from this directory):
    .venv/bin/python harness.py
"""
from nicegui import ui, app

# In-memory persistence: write once via POST /store, render later via GET /note.
STORE = {"note": "no note yet"}


@app.post("/store")
def store(payload: dict):
    STORE["note"] = payload.get("content", "")
    return {"ok": True}


@ui.page("/note")
def note_page():
    # VULNERABLE render path: stored note -> ui.markdown -> markdown2 (no safe_mode).
    ui.markdown(STORE["note"])


ui.run(host="127.0.0.1", port=8088, show=False, reload=False)
