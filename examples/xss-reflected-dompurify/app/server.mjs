import http from 'node:http';
import { URL } from 'node:url';

import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const host = process.env.HOST || '127.0.0.1';
const port = Number(process.env.PORT || '8092');

const purify = createDOMPurify(new JSDOM('').window);
purify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
purify.addHook('uponSanitizeAttribute', (node, data) => {
  if (node.getAttribute?.('data-trusted') === '1') {
    data.allowedAttributes.onerror = true;
  }
});
purify.sanitize('<img data-trusted="1" src="x" onerror="0">');

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname !== '/render') {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
    return;
  }

  const dirty = url.searchParams.get('html') || '';
  const clean = purify.sanitize(dirty);
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><title>DOMPurify PoC</title>${clean}`);
});

server.listen(port, host, () => {
  console.log(`DOMPurify PoC app listening on http://${host}:${port}`);
});
