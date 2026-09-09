"""Intentionally SAFE demo app for false-positive corpus (STEP 60).

Run: python examples/safe_app.py
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class SafeHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        print(f"[safe] {self.address_string()} - {format % args}")

    def _send(self, code: int, body: str, content_type: str = "text/html") -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        # Non-sensitive public CORS
        if self.path.startswith("/public/"):
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            self._send(200, "<html><body>Safe app</body></html>")
            return
        if path == "/custom-404-as-200":
            # Soft 404 that returns 200 with generic body
            self._send(200, "<html><body>Not Found (soft)</body></html>")
            return
        if path.startswith("/spa/") or path == "/spa":
            self._send(200, "<html><body>SPA fallback shell</body></html>")
            return
        if path == "/api/ok":
            self._send(200, '{"ok":true,"data":null}', "application/json")
            return
        if path == "/reflect":
            # HTML-encoded reflection
            raw = (qs.get("q") or [""])[0]
            encoded = (
                raw.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )
            self._send(200, f"<html><body>q={encoded}</body></html>")
            return
        if path == "/public/status":
            self._send(200, '{"status":"public"}', "application/json")
            return
        if path == "/docs/example":
            # Fake secret in documentation only
            self._send(
                200,
                "<html><body>Example API_KEY=docs-only-not-real</body></html>",
            )
            return
        if path == "/rate-weird":
            self.send_response(418)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"teapot rate")
            return
        if path == "/error-lookalike":
            self._send(200, "ERROR: syntax error near unexpected token", "text/plain")
            return
        self._send(404, "missing")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        if self.path.startswith("/public/"):
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET,OPTIONS")
        self.end_headers()


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8001), SafeHandler)
    print("Safe demo running at http://127.0.0.1:8001")
    server.serve_forever()


if __name__ == "__main__":
    main()
