"""Dashboard entry helper — prefer `magic-security serve` + web SPA."""

from __future__ import annotations

from pathlib import Path


def render_dashboard(db_path: str | Path = ".magic-security/magic.db") -> str:
    _ = db_path
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Magic Security</title>
  <style>
    body { font-family: "IBM Plex Sans", system-ui, sans-serif;
           background: #121417; color: #e8eaed; margin: 0; padding: 2.5rem; }
    a { color: #e8a838; }
    code, pre { font-family: "IBM Plex Mono", ui-monospace, monospace; }
    pre { background: #1c1f24; padding: 1rem; border: 1px solid #2a2f36; }
  </style>
</head>
<body>
  <h1>Magic Security</h1>
  <p>The interactive dashboard is served by the local control plane.</p>
  <pre>cd web &amp;&amp; npm install &amp;&amp; npm run build
magic-security serve</pre>
  <p>Then open <a href="http://127.0.0.1:8765/">http://127.0.0.1:8765/</a></p>
</body>
</html>
"""


def write_dashboard(
    path: str | Path,
    db_path: str | Path = ".magic-security/magic.db",
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_dashboard(db_path), encoding="utf-8")
    return destination
