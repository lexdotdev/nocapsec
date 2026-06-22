'use strict';
// Pinned vulnerable link-preview-js.
// Server-side fetch, observed via OAST.
//   GHSA-4gp8-rjrq-ch6q / CVE-2026-43897
const http = require('http');
const { getLinkPreview } = require('link-preview-js');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || '8099');

const server = http.createServer((req, res) => {
  const parsed = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'GET' && parsed.pathname === '/preview') {
    const url = parsed.searchParams.get('url') || '';
    (async () => {
      try {
        // Default options skip DNS guard.
        const data = await getLinkPreview(url, { timeout: 8000 });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: true, title: data.title || null }));
      } catch (e) {
        // Fetch already happened.
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    })();
    return;
  }
  if (req.url === '/') {
    res.setHeader('content-type', 'text/html');
    res.end('<form method=get action=/preview><input name=url><button>preview</button></form>');
    return;
  }
  res.statusCode = 404;
  res.end('not found');
});

server.listen(PORT, HOST, () => console.log(`link-preview harness on http://${HOST}:${PORT}`));
