"""Intentionally vulnerable local demo target for Magic_Security.

Run only on localhost. All credentials, identities, and data are fake test values.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "MagicDemo/0.9"

    def log_message(self, format: str, *args) -> None:
        print(f"[demo] {self.address_string()} - {format % args}")

    def _demo_user(self) -> str | None:
        header_user = self.headers.get("X-Demo-User")
        if header_user in {"A", "B", "ADMIN"}:
            return header_user

        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return None

        morsel = cookie.get("demo_session")
        if morsel and morsel.value in {"A", "B", "ADMIN"}:
            return morsel.value
        return None

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

    def _require_user(self) -> str | None:
        user = self._demo_user()
        if user is None:
            self._send(
                json.dumps({"detail": "authentication required"}),
                status=401,
                content_type="application/json",
            )
        return user

    @staticmethod
    def _account_id_for_user(user: str) -> int:
        return {
            "A": 101,
            "B": 202,
            "ADMIN": 303,
        }[user]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        user = self._demo_user()

        if path == "/":
            authenticated_link = (
                '<li><a href="/dashboard">Dashboard</a></li>'
                if user
                else ""
            )
            auth_cookie = (
                f"demo_session={user}; Path=/"
                if user
                else "session=fake-local-session; Path=/"
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
    <li><a href="/reflect?q=hello">Reflected input</a></li>
    <li><a href="/ssti?name=hello">SSTI demo</a></li>
    <li><a href="/sql?q=hello">SQL error demo</a></li>
    <li><a href="/crlf?value=hello">CRLF demo</a></li>
    <li><a href="/absolute">Host-header demo</a></li>
    {authenticated_link}
  </ul>
  <form action="/search" method="GET">
    <input name="q">
    <select name="category"><option>all</option></select>
  </form>
  <div id="output"></div>
  <script src="/static/app.js"></script>
</body>
</html>""",
                cookie=auth_cookie,
            )
            return

        if path == "/go":
            destination = query.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", destination)
            self.end_headers()
            return

        if path == "/reflect":
            reflected = query.get("q", [""])[0]
            self._send(
                f"""<!doctype html>
<html>
<body>
  <h1>Search preview</h1>
  <div id="result">{reflected}</div>
</body>
</html>"""
            )
            return

        if path == "/ssti":
            value = query.get("name", [""])[0]
            if value == "{{1337*7}}":
                value = "9359"
            self._send(
                f"<html><body>{value}</body></html>"
            )
            return

        if path == "/sql":
            value = query.get("q", [""])[0]
            if "'" in value:
                self._send(
                    "PostgreSQL ERROR: syntax error at or near quote",
                    status=500,
                    content_type="text/plain; charset=utf-8",
                )
                return
            self._send(
                "<html><body>search ok</body></html>"
            )
            return

        if path == "/crlf":
            value = query.get("value", [""])[0]
            headers: dict[str, str] = {}
            if "X-Magic-Security-Probe: verified" in value:
                headers["X-Magic-Security-Probe"] = "verified"
            self._send(
                "<html><body>redirect helper</body></html>",
                headers=headers,
            )
            return

        if path == "/sql-search":
            value = query.get("q", [""])[0]
            if "'" in value or '"' in value:
                self._send(
                    "SQL syntax error near quote",
                    status=500,
                    content_type="text/plain; charset=utf-8",
                )
            else:
                self._send(
                    "search ok",
                    content_type="text/plain; charset=utf-8",
                )
            return

        if path == "/template":
            value = query.get("name", [""])[0]
            if value == "{{1337*7}}":
                value = "9359"
            self._send(
                f"Hello {value}",
                content_type="text/html; charset=utf-8",
            )
            return

        if path == "/download":
            value = query.get("file", [""])[0]
            normalized = value.replace("\\", "/").lower()
            if normalized.endswith("etc/hosts"):
                self._send(
                    "127.0.0.1 localhost",
                    content_type="text/plain; charset=utf-8",
                )
            elif normalized.endswith("windows/win.ini"):
                self._send(
                    "[fonts]\n[extensions]",
                    content_type="text/plain; charset=utf-8",
                )
            else:
                self._send(
                    "not found",
                    status=404,
                    content_type="text/plain; charset=utf-8",
                )
            return

        if path == "/fetch":
            target_url = query.get("url", [""])[0]
            parsed_target = urlparse(target_url)
            if (
                parsed_target.scheme == "http"
                and parsed_target.hostname in {"127.0.0.1", "localhost"}
            ):
                try:
                    with urllib.request.urlopen(
                        target_url,
                        timeout=2,
                    ) as response:
                        status = response.status
                except Exception:
                    status = 599
                self._send(
                    json.dumps({"fetched_status": status}),
                    content_type="application/json",
                )
            else:
                self._send(
                    json.dumps(
                        {"detail": "demo allows loopback URLs only"}
                    ),
                    status=400,
                    content_type="application/json",
                )
            return

        if path == "/header":
            value = query.get("name", [""])[0]
            headers = {}
            if "X-Magic-Security-Probe: verified" in value:
                headers["X-Magic-Security-Probe"] = "verified"
            self._send(
                "header demo",
                headers=headers,
            )
            return

        if path == "/absolute":
            host = (
                self.headers.get("X-Forwarded-Host")
                or self.headers.get("Host", "localhost")
            )
            self._send(
                f"<html><body>Continue at http://{host}/landing</body></html>"
            )
            return

        if path == "/cors":
            origin = self.headers.get("Origin")
            headers: dict[str, str] = {}
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
                """const API_SECRET = "fake-client-secret-value";
const INTERNAL_API = "http://10.10.0.5/private";
fetch('/api/users?limit=20');
fetch('/api/me');
axios.post('/api/orders', {item: 1});
const graph = "/graphql";

if (location.hash && document.getElementById('output')) {
  document.getElementById('output').innerHTML =
    decodeURIComponent(location.hash.slice(1));
}

window.addEventListener('message', (event) => {
  if (document.getElementById('output')) {
    document.getElementById('output').innerHTML = event.data;
  }
});

function clientRedirectCandidate() {
  const target = location.search;
  if (false) {
    location.href = target;
  }
}

if (false) {
  new WebSocket('ws://127.0.0.1:8000/ws');
}

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
                            (
                                'const API_SECRET = "fake-client-secret-value";\n'
                                'const INTERNAL_API = "http://10.10.0.5/private";\n'
                                "export async function load(){ "
                                "return fetch('/api/users?limit=20') }"
                            )
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
                        "info": {
                            "title": "Magic Demo API",
                            "version": "0.9",
                        },
                        "paths": {
                            "/api/users": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "limit",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
                            "/sql-search": {
                                "get": {
                                    "parameters": [
                                        {"name": "q", "in": "query"}
                                    ]
                                }
                            },
                            "/template": {
                                "get": {
                                    "parameters": [
                                        {"name": "name", "in": "query"}
                                    ]
                                }
                            },
                            "/download": {
                                "get": {
                                    "parameters": [
                                        {"name": "file", "in": "query"}
                                    ]
                                }
                            },
                            "/fetch": {
                                "get": {
                                    "parameters": [
                                        {"name": "url", "in": "query"}
                                    ]
                                }
                            },
                            "/header": {
                                "get": {
                                    "parameters": [
                                        {"name": "name", "in": "query"}
                                    ]
                                }
                            },
                            "/api/login": {
                                "post": {
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "email": {"type": "string"},
                                                        "username": {"type": "string"},
                                                        "password": {"type": "string"}
                                                    }
                                                }
                                            }
                                        }
                                    }
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
                                                        "item": {
                                                            "type": "integer"
                                                        }
                                                    },
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "/api/profile": {
                                "post": {
                                    "requestBody": {
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "display_name": {
                                                            "type": "string"
                                                        }
                                                    },
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "/reflect": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "q",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
                            "/ssti": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "name",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
                            "/sql": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "q",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
                            "/crlf": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "value",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
                            "/go": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "next",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
                            "/graphql": {"post": {}},
                            "/api/private": {"get": {}},
                            "/api/me": {"get": {}},
                            "/api/public": {"get": {}},
                            "/api/user-settings": {"get": {}},
                            "/api/accounts/{account_id}": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "account_id",
                                            "in": "path",
                                        }
                                    ]
                                }
                            },
                            "/api/account-detail": {
                                "get": {
                                    "parameters": [
                                        {
                                            "name": "account_id",
                                            "in": "query",
                                        }
                                    ]
                                }
                            },
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
                        "info": {
                            "title": "Magic Demo API",
                            "version": "0.9",
                        },
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
                                "phone": "+490000000000",
                            }
                        ]
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/api/private":
            self._send(
                json.dumps(
                    {"detail": "authentication required"}
                ),
                status=401,
                content_type="application/json",
            )
            return

        if path == "/api/me":
            if not user:
                self._send(
                    json.dumps(
                        {"detail": "authentication required"}
                    ),
                    status=401,
                    content_type="application/json",
                )
                return

            account_id = self._account_id_for_user(user)
            headers = {
                "Cache-Control": "public, max-age=120",
            }
            origin = self.headers.get("Origin")
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"

            self._send(
                json.dumps(
                    {
                        "user": {
                            "id": user,
                            "display_name": f"Demo User {user}",
                            "account_id": account_id,
                        }
                    }
                ),
                content_type="application/json",
                cookie=f"demo_session={user}; Path=/",
                headers=headers,
            )
            return

        if path == "/api/public":
            self._send(
                json.dumps(
                    {
                        "service": "magic-demo",
                        "public": True,
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/dashboard":
            if not user:
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
  <form action="/api/profile" method="POST">
    <input name="display_name">
  </form>
  <script>
    localStorage.setItem('access_token', 'fake-browser-token');
    fetch('/api/user-settings');
  </script>
</body>
</html>""",
                cookie=f"demo_session={user}; Path=/",
            )
            return

        if path == "/api/user-settings":
            if not user:
                self._send(
                    json.dumps(
                        {"detail": "authentication required"}
                    ),
                    status=401,
                    content_type="application/json",
                )
                return

            self._send(
                json.dumps(
                    {
                        "theme": (
                            "dark"
                            if user == "A"
                            else "light"
                        ),
                        "notifications": True,
                    }
                ),
                content_type="application/json",
            )
            return

        if path.startswith("/api/accounts/"):
            if not user:
                self._send(
                    json.dumps(
                        {"detail": "authentication required"}
                    ),
                    status=401,
                    content_type="application/json",
                )
                return

            try:
                account_id = int(
                    path.rsplit("/", 1)[-1]
                )
            except ValueError:
                self._send(
                    json.dumps({"detail": "not found"}),
                    status=404,
                    content_type="application/json",
                )
                return

            if account_id not in {101, 202, 303}:
                self._send(
                    json.dumps({"detail": "not found"}),
                    status=404,
                    content_type="application/json",
                )
                return

            self._send(
                json.dumps(
                    {
                        "account_id": account_id,
                        "email": (
                            f"demo-{account_id}@example.test"
                        ),
                        "plan": "demo",
                    }
                ),
                content_type="application/json",
            )
            return

        if path == "/api/account-detail":
            if not user:
                self._send(
                    json.dumps(
                        {"detail": "authentication required"}
                    ),
                    status=401,
                    content_type="application/json",
                )
                return

            raw_account = query.get(
                "account_id",
                [None],
            )[0]

            try:
                account_id = (
                    int(raw_account)
                    if raw_account
                    else None
                )
            except ValueError:
                account_id = None

            if account_id not in {101, 202, 303}:
                self._send(
                    json.dumps({"detail": "not found"}),
                    status=404,
                    content_type="application/json",
                )
                return

            self._send(
                json.dumps(
                    {
                        "account_id": account_id,
                        "status": "active",
                    }
                ),
                content_type="application/json",
            )
            return

        if path in {
            "/search",
            "/products",
            "/settings",
        }:
            self._send(
                "<html><body>demo response</body></html>"
            )
            return

        self._send(
            "not found",
            status=404,
            content_type="text/plain; charset=utf-8",
        )

    def do_TRACE(self) -> None:
        marker = self.headers.get("X-Magic-Security-Trace", "")
        self._send(
            f"TRACE / HTTP/1.1\nX-Magic-Security-Trace: {marker}\n",
            content_type="message/http",
        )

    def do_OPTIONS(self) -> None:
        self._send(
            "",
            status=204,
            headers={"Allow": "GET, POST, OPTIONS, TRACE"},
        )

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/login":
            length = int(
                self.headers.get("Content-Length", "0") or "0"
            )
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {}

            email = payload.get("email")
            username = payload.get("username")
            password = payload.get("password")

            sql_bypass = any(
                isinstance(value, str)
                and " OR " in value.upper()
                for value in (email, username)
            )
            nosql_bypass = any(
                isinstance(value, dict)
                and "$ne" in value
                for value in (email, username, password)
            )

            if sql_bypass or nosql_bypass:
                self._send(
                    json.dumps(
                        {"user": {"id": "demo-auth-bypass"}}
                    ),
                    content_type="application/json",
                    cookie="demo_session=A; Path=/",
                )
            else:
                self._send(
                    json.dumps(
                        {"detail": "invalid credentials"}
                    ),
                    status=401,
                    content_type="application/json",
                )
            return

        if path == "/graphql":
            length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
                or "0"
            )
            raw = self.rfile.read(length)

            try:
                payload = json.loads(
                    raw.decode("utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                payload = {}

            query = str(payload.get("query") or "")

            if "__schema" in query:
                self._send(
                    json.dumps(
                        {
                            "data": {
                                "__schema": {
                                    "queryType": {
                                        "name": "Query"
                                    },
                                    "mutationType": {
                                        "name": "Mutation"
                                    },
                                }
                            }
                        }
                    ),
                    content_type="application/json",
                )
                return

            self._send(
                json.dumps(
                    {
                        "errors": [
                            {
                                "message": "demo GraphQL error",
                                "extensions": {
                                    "stacktrace": [
                                        "resolver.py:42"
                                    ]
                                },
                            }
                        ]
                    }
                ),
                status=400,
                content_type="application/json",
            )
            return

        if path == "/api/orders":
            self._send(
                '{"ok": true}',
                content_type="application/json",
            )
            return

        if path == "/api/profile":
            user = self._require_user()
            if not user:
                return

            self._send(
                json.dumps(
                    {
                        "ok": True,
                        "user": user,
                    }
                ),
                content_type="application/json",
            )
            return

        self._send(
            "not found",
            status=404,
            content_type="text/plain; charset=utf-8",
        )


def main() -> None:
    port = (
        int(sys.argv[1])
        if len(sys.argv) > 1
        else 8000
    )

    server = ThreadingHTTPServer(
        ("127.0.0.1", port),
        DemoHandler,
    )

    print(
        "Intentionally vulnerable demo running at "
        f"http://127.0.0.1:{port}"
    )
    print(
        "All credentials and data are fake. "
        "Stop with Ctrl+C."
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
