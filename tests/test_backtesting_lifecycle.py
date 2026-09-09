"""STEP 62 — backtesting lifecycle; WORSENED must be strict."""

from __future__ import annotations

from magic_security.backtesting import (
    apply_history,
    build_scan_snapshot,
    diff_snapshots,
)
from magic_security.models import CrawlResult, Finding, FindingKind, Severity


def _finding(title: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        kind=FindingKind.VULNERABILITY,
        url="http://127.0.0.1:8000/vuln",
        description="d",
        evidence="e",
        remediation="r",
        confidence=1.0,
        check_id="test.vuln",
    )


def test_backtesting_lifecycle_new_resolved_reintroduced_worsened():
    crawl = CrawlResult(target="http://127.0.0.1:8000/")
    crawl.check_coverage = [{"check_id": "x", "status": "executed"}]
    modes = {"http": True, "browser": True, "active": True}

    clean = build_scan_snapshot(crawl, [], modes=modes)
    empty_diff = diff_snapshots(clean, clean)
    baseline = apply_history(clean, clean, empty_diff)

    with_vuln = build_scan_snapshot(crawl, [_finding("XSS")], modes=modes)
    fp = with_vuln["findings"][0]["fingerprint"]
    diff1 = diff_snapshots(baseline, with_vuln)
    assert any(item.get("fingerprint") == fp for item in diff1["findings"]["new"])

    baseline2 = apply_history(baseline, with_vuln, diff1)

    fixed = build_scan_snapshot(crawl, [], modes=modes)
    diff2 = diff_snapshots(baseline2, fixed)
    assert any(item.get("fingerprint") == fp for item in diff2["findings"]["resolved"])

    baseline3 = apply_history(baseline2, fixed, diff2)

    again = build_scan_snapshot(crawl, [_finding("XSS")], modes=modes)
    diff3 = diff_snapshots(baseline3, again)
    assert any(item.get("fingerprint") == fp for item in diff3["findings"]["reintroduced"])

    baseline4 = apply_history(baseline3, again, diff3)
    worse = build_scan_snapshot(
        crawl,
        [_finding("XSS", severity=Severity.CRITICAL)],
        modes=modes,
    )
    assert worse["findings"][0]["fingerprint"] == fp
    diff4 = diff_snapshots(baseline4, worse)
    assert diff4["summary"]["worsened"] == 1
    assert any(
        item.get("after", {}).get("fingerprint") == fp
        for item in diff4["findings"]["worsened"]
    )
    assert not any(item.get("fingerprint") == fp for item in diff4["findings"]["new"])

    reduced = build_scan_snapshot(crawl, [_finding("XSS")], modes={"http": True})
    diff5 = diff_snapshots(baseline4, reduced)
    assert diff5["coverage"]["equivalent"] is False
