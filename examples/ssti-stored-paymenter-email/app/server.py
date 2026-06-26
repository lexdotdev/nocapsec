#!/usr/bin/env python3
"""Paymenter-shaped harness: write/trigger/read for Blade SSTI."""

import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

_template = ""
_latest_email = ""

BLADE_ARITH = re.compile(r"\{\{\s*(\d+)\*(\d+)\s*\}\}")


def render_blade(template):
    return BLADE_ARITH.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), template)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global _template, _latest_email
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()

        if self.path == "/admin/products/42":
            vals = parse_qs(body, keep_blank_values=True)
            _template = vals.get("email_template", [""])[0]
            self.send_response(200)
            self.end_headers()
        elif self.path == "/admin/services/99/actions/create":
            _latest_email = render_blade(_template)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_error(404)

    def do_GET(self):
        if self.path == "/admin/email-logs/latest":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(_latest_email.encode())
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    addr = ("127.0.0.1", 8090)
    print(f"listening on http://{addr[0]}:{addr[1]}")
    HTTPServer(addr, Handler).serve_forever()
