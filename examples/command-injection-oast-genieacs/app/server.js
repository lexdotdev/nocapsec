'use strict';
// GenieACS command-injection sink.
// POST /ping feeds host into the shell.
// OAST DNS proves execution.
const http = require('http');
const { exec } = require('child_process');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || '8095');

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/ping') {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const host = new URLSearchParams(body).get('host') || '';
      // Shell sink.
      const cmd = `ping -c 1 ${host}`;
      exec(cmd, { timeout: 8000 }, (err, stdout) => {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ ok: !err, output: (stdout || '').slice(0, 200) }));
      });
    });
    return;
  }
  res.statusCode = 404;
  res.end('not found');
});

server.listen(PORT, HOST, () => console.log(`genieacs-ping harness on http://${HOST}:${PORT}`));
