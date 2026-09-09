"""Minimal local dashboard HTML (STEP 49)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from magic_security.persistence import Persistence


def render_dashboard(db_path: str | Path = ".magic-security/magic.db") -> str:
    persistence = Persistence(Path(db_path))
    persistence.init_schema()
    targets = persistence.list_targets()

    target_rows = "".join(
        f"<tr><td>{item.get('id')}</td><td>{item.get('base_url')}</td>"
        f"<td>{item.get('environment')}</td></tr>"
        for item in targets
    ) or "<tr><td colspan='3'>No targets yet</td></tr>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Magic Security Dashboard</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 2rem; background: #f4f1ea; color: #222; }}
    h1,h2 {{ font-family: 'Segoe UI', sans-serif; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; }}
    th,td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; }}
    th {{ background: #ece6da; }}
    .note {{ color: #555; }}
  </style>
</head>
<body>
  <h1>Magic Security</h1>
  <p class="note">Local dashboard — Targets, latest status, regressions, findings, coverage, history.</p>
  <h2>Targets</h2>
  <table>
    <thead><tr><th>ID</th><th>URL</th><th>Environment</th></tr></thead>
    <tbody>{target_rows}</tbody>
  </table>
  <h2>How to use</h2>
  <ol>
    <li>Register targets via CLI <code>magic-security target add</code> or API <code>POST /targets</code>.</li>
    <li>Run scans via CLI or <code>POST /scans</code>.</li>
    <li>Set baselines and use <code>--fail-on-policy</code> / CI gate for regressions.</li>
  </ol>
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
