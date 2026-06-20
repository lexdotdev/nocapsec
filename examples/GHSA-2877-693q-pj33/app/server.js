'use strict';
// Faithful reproduction of the GenieACS command-injection sink (GHSA-2877-693q-pj33
// / CVE-2021-46704). The real GenieACS UI exposes this via GET /api/ping/:host,
// which calls ping(host) in lib/ping.ts:
//
//     cmd = `ping -w 1 -i 0.2 -c 3 ${host}`;   // host interpolated into a shell string
//     exec(cmd, (err, stdout) => { ... });     // child_process.exec -> /bin/sh
//
// The host flows unsanitized into a shell command, so the server resolves and
// pings an attacker-named host (and would run injected shell commands). nocapsec's
// command_injection.oast validator injects the OAST host into a request *body*
// field, so this harness exposes the identical sink over POST /ping (form field
// `host`) instead of GenieACS's GET path param. The `-c 1` form is used so the
// command runs on macOS/BSD as well as Linux; the out-of-band DNS lookup of the
// injected host is what proves the sink executed.
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
      // Vulnerable construction: host interpolated straight into the shell string.
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
