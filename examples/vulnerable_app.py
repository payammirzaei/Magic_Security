"""Intentionally vulnerable local demo target for Magic_Security.

Run only on localhost. All secrets are fake test values.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "MagicDemo/0.1"

    def log_message(self, format: str, *args) -> None:
        print(f"[demo] {self.address_string()} - {format % args}")

    def _send(self, body: str, *, status: int = 200, content_type: str = "text/html; charset=utf-8", cookie: str | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(
                """<!doctype html>
<html>
<head><title>Magic Security vulnerable demo</title></head>
<body>
  <h1>Magic Security vulnerable demo</h1>
  <ul>
    <li><a href="/docs">API docs</a></li>
    <li><a href="/files/">Files</a></li>
    <li><a href="/stacktrace">Debug error</a></li>
  </ul>
  <form action="/search" method="GET"><input name="q"></form>
</body>
</html>""",
                cookie="session=fake-local-session; Path=/",
            )
            return

        if self.path == "/docs":
            self._send(
                """<!doctype html>
<html><head><title>Swagger UI</title></head>
<body><h1>Swagger / OpenAPI documentation</h1></body></html>"""
            )
            return

        if self.path == "/files/":
            self._send(
                """<!doctype html>
<html><head><title>Index of /files/</title></head>
<body><h1>Index of /files/</h1><a href="backup.txt">backup.txt</a></body></html>"""
            )
            return

        if self.path == "/files/backup.txt":
            self._send("demo backup file", content_type="text/plain; charset=utf-8")
            return

        if self.path == "/stacktrace":
            self._send(
                """<!doctype html><html><body><pre>
Traceback (most recent call last):
  File "app.py", line 42, in handler
RuntimeError: demo exception
</pre></body></html>"""
            )
            return

        if self.path == "/.env":
            self._send(
                "DATABASE_URL=postgres://demo:fake-password@localhost/demo\n"
                "API_KEY=fake-local-api-key\n"
                "DEBUG=true\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if self.path == "/.git/HEAD":
            self._send("ref: refs/heads/main\n", content_type="text/plain; charset=utf-8")
            return

        if self.path == "/openapi.json":
            self._send(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "info": {"title": "Magic Demo API", "version": "0.1"},
                        "paths": {"/demo": {"get": {}}},
                    }
                ),
                content_type="application/json",
            )
            return

        if self.path == "/swagger.json":
            self._send(
                json.dumps(
                    {
                        "swagger": "2.0",
                        "info": {"title": "Magic Demo API", "version": "0.1"},
                        "paths": {},
                    }
                ),
                content_type="application/json",
            )
            return

        if self.path.startswith("/search"):
            self._send("<html><body>search demo</body></html>")
            return

        self._send("not found", status=404, content_type="text/plain; charset=utf-8")


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = ThreadingHTTPServer(("127.0.0.1", port), DemoHandler)
    print(f"Intentionally vulnerable demo running at http://127.0.0.1:{port}")
    print("All credentials are fake. Stop with Ctrl+C.")
    server.serve_forever()


if __name__ == "__main__":
    main()
