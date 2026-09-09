"""Standalone HTML security report (STEP 42)."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from magic_security.models import CrawlResult, Finding
from magic_security.reporting import build_report


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html_report(report: dict[str, Any]) -> str:
    validity = report.get("scan_validity") or {}
    summary = report.get("summary") or {}
    decision = report.get("decision") or {}
    regressions = decision.get("regressions") or {}
    findings = report.get("findings") or []
    repo = report.get("repository_findings") or []
    coverage = report.get("coverage") or {}

    finding_rows = []
    for item in findings:
        finding_rows.append(
            "<tr>"
            f"<td>{_esc(item.get('severity'))}</td>"
            f"<td>{_esc(item.get('kind'))}</td>"
            f"<td>{_esc(item.get('title'))}</td>"
            f"<td>{_esc('verified' if item.get('verified') else item.get('confidence_level'))}</td>"
            f"<td>{_esc(item.get('url'))}</td>"
            f"<td>{_esc(item.get('evidence'))}</td>"
            f"<td>{_esc(item.get('remediation'))}</td>"
            "</tr>"
        )

    regression_blocks = []
    for label, key in (
        ("New verified", "new_verified"),
        ("Reintroduced", "reintroduced"),
        ("Worsened", "worsened"),
        ("New exposures", "new_exposures"),
        ("Resolved", "resolved"),
    ):
        items = regressions.get(key) or []
        if not items:
            continue
        lis = "".join(
            f"<li>[{_esc(i.get('severity'))}] {_esc(i.get('title'))}</li>"
            for i in items[:30]
        )
        regression_blocks.append(
            f"<h3>{_esc(label)} ({len(items)})</h3><ul>{lis}</ul>"
        )

    validity_note = ""
    if validity.get("zero_tests_executed"):
        validity_note = (
            "<p class='warn'><strong>0 tests executed</strong> — "
            "not the same as a clean scan with 0 findings.</p>"
        )
    elif summary.get("findings") == 0:
        validity_note = (
            "<p class='ok'><strong>0 findings</strong> with tests executed.</p>"
        )

    repo_rows = "".join(
        "<tr>"
        f"<td>source</td>"
        f"<td>{_esc(item.get('severity'))}</td>"
        f"<td>{_esc(item.get('title'))}</td>"
        f"<td>{_esc(item.get('location'))}</td>"
        f"<td>{_esc(item.get('evidence'))}</td>"
        "</tr>"
        for item in repo[:50]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Magic Security Report — {_esc(report.get('target'))}</title>
  <style>
    body {{ font-family: Georgia, 'Times New Roman', serif; margin: 2rem; color: #1a1a1a; background: #f7f4ef; }}
    h1,h2,h3 {{ font-family: 'Segoe UI', sans-serif; }}
    .card {{ background: #fff; border: 1px solid #d9d2c5; padding: 1rem 1.25rem; margin-bottom: 1rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    th, td {{ border-bottom: 1px solid #e5dfd3; text-align: left; padding: 0.45rem 0.35rem; vertical-align: top; }}
    th {{ background: #efe9df; }}
    .warn {{ color: #8a4b08; }}
    .ok {{ color: #1f6b3a; }}
    .meta {{ color: #555; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <h1>Magic Security Report</h1>
  <p class="meta">Target: {_esc(report.get('target'))} · Scanner {_esc(report.get('scanner_version'))} · Schema {_esc(report.get('report_schema_version'))}</p>

  <div class="card">
    <h2>Executive Summary</h2>
    <p>Status: <strong>{_esc(validity.get('status'))}</strong></p>
    <p>Checks executed: {_esc(validity.get('checks_executed'))} · Failed: {_esc(validity.get('checks_failed'))}</p>
    <p>Findings: {_esc(summary.get('findings'))} (verified {_esc(summary.get('verified'))}) · Vulnerabilities {_esc(summary.get('vulnerabilities'))} · Exposures {_esc(summary.get('exposures'))}</p>
    {validity_note}
  </div>

  <div class="card">
    <h2>Regressions</h2>
    {''.join(regression_blocks) or '<p>No baseline diff attached.</p>'}
  </div>

  <div class="card">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Kind</th><th>Title</th><th>Confidence</th><th>URL</th><th>Evidence</th><th>Remediation</th></tr></thead>
      <tbody>{''.join(finding_rows) or '<tr><td colspan="7">None</td></tr>'}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Source Findings</h2>
    <p class="meta">Source findings are not runtime proof.</p>
    <table>
      <thead><tr><th>Source</th><th>Severity</th><th>Title</th><th>Location</th><th>Evidence</th></tr></thead>
      <tbody>{repo_rows or '<tr><td colspan="5">None</td></tr>'}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Coverage</h2>
    <p>Pack keys: {_esc(', '.join((coverage.get('packs') or {}).keys()))}</p>
    <p>Categories: {_esc(len(coverage.get('categories') or []))}</p>
  </div>

  <div class="card">
    <h2>Attack Surface</h2>
    <pre>{_esc(report.get('attack_surface'))}</pre>
  </div>
</body>
</html>
"""


def write_html_report(
    path: str | Path,
    crawl: CrawlResult,
    findings: list[Finding],
    **kwargs: Any,
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(crawl, findings, **kwargs)
    destination.write_text(render_html_report(report), encoding="utf-8")
    return destination
