"""STEP 54 — secret leak audit across report channels."""

from __future__ import annotations

from magic_security.models import CrawlResult, Finding, FindingKind, Severity
from magic_security.persistence import Persistence
from magic_security.redaction import Redactor
from magic_security.reporting import build_report, render_terminal_report, write_json_report
from magic_security.reporting_html import render_html_report
from magic_security.backtesting import build_scan_snapshot, write_snapshot


SEED = "SEED_SECRET_LEAK_AUDIT_9f3a2c1b"


def _seeded_finding() -> Finding:
    return Finding(
        title="Leak probe",
        severity=Severity.HIGH,
        kind=FindingKind.EXPOSURE,
        url=f"http://127.0.0.1:8000/x?token={SEED}",
        description=f"token={SEED}",
        evidence=f"Authorization: Bearer {SEED}",
        remediation="rotate",
        confidence=0.9,
    )


def test_secret_absent_from_report_snapshot_terminal_html_db(tmp_path):
    redactor = Redactor()
    crawl = CrawlResult(target="http://127.0.0.1:8000/")
    crawl.check_coverage = [{"check_id": "x", "status": "executed"}]
    finding = _seeded_finding()
    report = redactor.scrub_report(build_report(crawl, [finding]))
    terminal = render_terminal_report(report)
    html = render_html_report(report)
    json_path = tmp_path / "report.json"
    write_json_report(json_path, crawl, [finding])
    json_text = json_path.read_text(encoding="utf-8")

    assert SEED not in str(report)
    assert SEED not in terminal
    assert SEED not in html
    assert SEED not in json_text

    snap = build_scan_snapshot(crawl, [finding])
    snap_path = tmp_path / "snap.json"
    write_snapshot(snap_path, snap)
    assert SEED not in snap_path.read_text(encoding="utf-8")

    db = Persistence(tmp_path / "t.db")
    db.init_schema()
    scan_id = db.save_scan(target_id="t", report=report, snapshot=snap)
    row = db.get_scan(scan_id)
    assert SEED not in str(row)

    headers = redactor.redact_headers({"Authorization": f"Bearer {SEED}"})
    assert SEED not in str(headers)
    cookies = redactor.redact_cookies({"session": SEED})
    assert SEED not in str(cookies)
    assert SEED not in redactor.redact_text(f"password={SEED}")
