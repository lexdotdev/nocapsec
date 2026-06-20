'use strict';
// Thin HTTP harness around the REAL pinned vulnerable link-preview-js@4.0.0.
// POST /preview with form field `url` -> getLinkPreview(url) extracts the URL and
// (in 4.0.0, with no resolveDNSHost option) calls fetch() on it server-side with
// no SSRF guard. This is the unfurl/link-preview path used by chat/CMS apps: a
// stored, attacker-controlled link is fetched out-of-band by the server. The
// blind callback is observed only via the OAST receiver.
//   GHSA-4gp8-rjrq-ch6q / CVE-2026-43897
const http = require('http');
const { getLinkPreview } = require('link-preview-js');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || '8099');

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/preview') {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', async () => {
      const url = new URLSearchParams(body).get('url') || '';
      try {
        // Default options: no resolveDNSHost guard -> unconditional server-side fetch.
        const data = await getLinkPreview(url, { timeout: 8000 });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: true, title: data.title || null }));
      } catch (e) {
        // The fetch still fired before any parse/validation error surfaced.
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }
  if (req.url === '/') {
    res.setHeader('content-type', 'text/html');
    res.end('<form method=post action=/preview><input name=url><button>preview</button></form>');
    return;
  }
  res.statusCode = 404;
  res.end('not found');
});

server.listen(PORT, HOST, () => console.log(`link-preview harness on http://${HOST}:${PORT}`));
