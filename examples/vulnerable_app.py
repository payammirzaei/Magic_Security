"""Intentionally vulnerable local demo target for Magic_Security.

Run only on localhost. All secrets are fake test values.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "MagicDemo/0.3"

    def log_message(self, format: str, *args) -> None:
        print(f"[demo] {self.address_string()} - {format % args}")

    def _send(
        self,
        body: str,
        *,
        status: int = 200,
        content_type: str = "text/html; charset=utf-8",
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            user = self.headers.get("X-Demo-User")
            authenticated_link = (
                '<li><a href="/dashboard">Dashboard</a></li>'
                if user in {"A", "B"}
                else ""
            )
            self._send(
                f"""<!doctype html>
<html>
<head><title>Magic Security vulnerable demo</title></head>
<body>
  <h1>Magic Security vulnerable demo</h1>
  <ul>
    <li><a href="/docs">API docs</a></li>
    <li><a href="/files/">Files</a></li>
    <li><a href="/stacktrace">Debug error</a></li>
    <li><a href="/products?page=2&sort=name">Products</a></li>
    <li><a href="/go?next=/products">Redirect helper</a></li>
    <li><a href="/cors">CORS demo</a></li>
    {authenticated_link}
  </ul>
  <form action="/search" method="GET">
    <input name="q">
    <select name="category"><option>all</option></select>
  </form>
  <script src="/static/app.js"></script>
</body>
</html>""",
                cookie="session=fake-local-session; Path=/",
            )
            return

        if path == "/go":
            destination = query.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", destination)
            self.end_headers()
            return

        if path == "/cors":
            origin = self.headers.get("Origin")
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(
                '{"demo":"cors","private":"fake-profile-data"}',
                content_type="application/json",
                headers=headers,
            )
            return

        if path == "/static/app.js":
            self._send(
                """fetch('/api/users?limit=20');
fetch('/api/me');
axios.post('/api/orders', {item: 1});
const graph = "/graphql";
//# sourceMappingURL=app.js.map
""",
                content_type="application/javascript",
            )
            return

        if path == "/static/app.js.map":
            self._send(
                json.dumps(
                    {
                        "version": 3,
                        "file": "app.js",
                        "sources": ["src/app.ts"],
                        "sourcesContent": [
                            "export async function load(){ return fetch('/api/users?limit=20') }"
                        ],
                        "names": [],
                        "mappings": "",
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/docs":
            self._send(
                """<!doctype html>
<html><head><title>Swagger UI</title></head>
<body><h1>Swagger / OpenAPI documentation</h1></body></html>"""
            )
            return

        if path == "/files/":
            self._send(
                """<!doctype html>
<html><head><title>Index of /files/</title></head>
<body><h1>Index of /files/</h1><a href="backup.txt">backup.txt</a></body></html>"""
            )
            return

        if path == "/files/backup.txt":
            self._send(
                "demo backup file",
                content_type="text/plain; charset=utf-8",
            )
            return

        if path == "/stacktrace":
            self._send(
                """<!doctype html><html><body><pre>
Traceback (most recent call last):
  File "app.py", line 42, in handler
RuntimeError: demo exception
</pre></body></html>"""
            )
            return

        if path == "/.env":
            self._send(
                "DATABASE_URL=postgres://demo:fake-password@localhost/demo\n"
                "API_KEY=fake-local-api-key\n"
                "DEBUG=true\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if path == "/.git/HEAD":
            self._send(
                "ref: refs/heads/main\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if path == "/openapi.json":
            self._send(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "info": {"title": "Magic Demo API", "version": "0.3"},
                        "paths": {
                            "/api/users": {
                                "get": {
                                    "parameters": [
                                        {"name": "limit", "in": "query"}
                                    ]
                                }
                            },
                            "/api/orders": {
                                "post": {
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "item": {"type": "integer"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "/go": {
                                "get": {
                                    "parameters": [
                                        {"name": "next", "in": "query"}
                                    ]
                                }
                            },
                            "/api/private": {
                                "get": {}
                            },
                            "/api/me": {
                                "get": {}
                            },
                            "/api/public": {
                                "get": {}
                            },
                            "/api/accounts/{account_id}": {
                                "get": {
                                    "parameters": [
                                        {"name": "account_id", "in": "path"}
                                    ]
                                }
                            }
                        },
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/swagger.json":
            self._send(
                json.dumps(
                    {
                        "swagger": "2.0",
                        "info": {"title": "Magic Demo API", "version": "0.3"},
                        "paths": {},
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/api/users":
            self._send(
                json.dumps(
                    {
                        "users": [
                            {
                                "id": 1,
                                "name": "Demo User",
                                "email": "demo.user@example.test",
                                "phone": "+490000000000"
                            }
                        ]
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/api/private":
            self._send(
                json.dumps({"detail": "authentication required"}),
                status=401,
                content_type="application/json",
            )
            return

        if path == "/api/me":
            user = self.headers.get("X-Demo-User")
            if user not in {"A", "B"}:
                self._send(
                    json.dumps({"detail": "authentication required"}),
                    status=401,
                    content_type="application/json",
                )
                return
            account_id = 101 if user == "A" else 202
            self._send(
                json.dumps(
                    {
                        "user": {
                            "id": user,
                            "display_name": f"Demo User {user}",
                            "account_id": account_id
                        }
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/api/public":
            self._send(
                json.dumps({"service": "magic-demo", "public": True}),
                content_type="application/json",
            )
            return

        if path == "/dashboard":
            user = self.headers.get("X-Demo-User")
            if user not in {"A", "B"}:
                self._send(
                    "<html><body>authentication required</body></html>",
                    status=401,
                )
                return

            self._send(
                f"""<!doctype html>
<html>
<body>
  <h1>Dashboard {user}</h1>
  <a href="/settings?tab=profile">Settings</a>
  <script>
    fetch('/api/user-settings');
  </script>
</body>
</html>"""
            )
            return

        if path == "/api/user-settings":
            user = self.headers.get("X-Demo-User")
            if user not in {"A", "B"}:
                self._send(
                    json.dumps({"detail": "authentication required"}),
                    status=401,
                    content_type="application/json",
                )
                return

            self._send(
                json.dumps(
                    {
                        "theme": "dark" if user == "A" else "light",
                        "notifications": True,
                    }
                ),
                content_type="application/json",
            )
            return

        if path.startswith("/api/accounts/"):
            user = self.headers.get("X-Demo-User")
            if user not in {"A", "B"}:
                self._send(
                    json.dumps({"detail": "authentication required"}),
                    status=401,
                    content_type="application/json",
                )
                return

            try:
                account_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self._send(
                    json.dumps({"detail": "not found"}),
                    status=404,
                    content_type="application/json",
                )
                return

            if account_id not in {101, 202}:
                self._send(
                    json.dumps({"detail": "not found"}),
                    status=404,
                    content_type="application/json",
                )
                return

            # Intentionally vulnerable: authenticated users can read either account.
            self._send(
                json.dumps(
                    {
                        "account_id": account_id,
                        "email": f"demo-{account_id}@example.test",
                        "plan": "demo",
                    }
                ),
                content_type="application/json",
            )
            return

        if path in {"/search", "/products", "/graphql", "/settings"}:
            self._send("<html><body>demo response</body></html>")
            return

        self._send(
            "not found",
            status=404,
            content_type="text/plain; charset=utf-8",
        )

    def do_POST(self) -> None:
        if self.path == "/api/orders":
            self._send('{"ok": true}', content_type="application/json")
            return
        self._send(
            "not found",
            status=404,
            content_type="text/plain; charset=utf-8",
        )


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = ThreadingHTTPServer(("127.0.0.1", port), DemoHandler)
    print(
        f"Intentionally vulnerable demo running at "
        f"http://127.0.0.1:{port}"
    )
    print("All credentials are fake. Stop with Ctrl+C.")
    server.serve_forever()


if __name__ == "__main__":
    main()
