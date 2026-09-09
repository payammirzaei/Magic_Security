from magic_security.backtesting import (
    apply_history,
    build_scan_snapshot,
    diff_snapshots,
)
from magic_security.models import (
    CrawlResult,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    Severity,
)


def _finding(
    title: str,
    severity: Severity,
    url: str,
    *,
    check_id: str,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        kind=FindingKind.VULNERABILITY,
        url=url,
        description="proof",
        evidence="proof",
        remediation="fix",
        confidence=1.0,
        check_id=check_id,
    )


def _crawl(endpoint_url: str) -> CrawlResult:
    crawl = CrawlResult(target="http://localhost:8000")
    crawl.normalized_endpoints = [
        NormalizedEndpoint(
            url=endpoint_url,
            method="GET",
            parameters=("id",),
            sources=("http",),
        )
    ]
    crawl.coverage_registry = [
        {"category": "Authorization / Access Control", "status": "Partially Tested"}
    ]
    return crawl


def test_snapshot_diff_detects_new_resolved_and_worsened_findings():
    baseline = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/123456"),
        [
            _finding(
                "BOLA",
                Severity.MEDIUM,
                "http://localhost:8000/api/orders/123456",
                check_id="authorization.bola.read",
            ),
            _finding(
                "Old XSS",
                Severity.HIGH,
                "http://localhost:8000/search?q=",
                check_id="xss.reflected.execution",
            ),
        ],
        modes={"active": True, "browser": True, "auth_contexts": 2},
        created_at="2026-09-09T08:00:00+00:00",
    )

    current = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/987654"),
        [
            _finding(
                "BOLA wording changed",
                Severity.HIGH,
                "http://localhost:8000/api/orders/987654",
                check_id="authorization.bola.read",
            ),
            _finding(
                "New redirect",
                Severity.MEDIUM,
                "http://localhost:8000/go?next=",
                check_id="redirect.open",
            ),
        ],
        modes={"active": True, "browser": True, "auth_contexts": 2},
        created_at="2026-09-09T09:00:00+00:00",
    )

    diff = diff_snapshots(baseline, current)

    assert diff["summary"]["new"] == 1
    assert diff["summary"]["resolved"] == 1
    assert diff["summary"]["worsened"] == 1
    assert diff["summary"]["surface_added"] == 0
    assert diff["summary"]["surface_removed"] == 0
    assert diff["coverage"]["equivalent"] is True


def test_history_marks_reintroduced_finding():
    first = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/123456"),
        [
            _finding(
                "XSS",
                Severity.HIGH,
                "http://localhost:8000/search?q=",
                check_id="xss.reflected.execution",
            )
        ],
        created_at="2026-09-09T08:00:00+00:00",
    )
    clean = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/123456"),
        [],
        created_at="2026-09-09T09:00:00+00:00",
    )
    first_diff = diff_snapshots(first, clean)
    apply_history(first, clean, first_diff)

    reintroduced = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/123456"),
        [
            _finding(
                "XSS renamed",
                Severity.HIGH,
                "http://localhost:8000/search?q=",
                check_id="xss.reflected.execution",
            )
        ],
        created_at="2026-09-09T10:00:00+00:00",
    )
    second_diff = diff_snapshots(clean, reintroduced)

    assert second_diff["summary"]["reintroduced"] == 1
    assert second_diff["summary"]["new"] == 0


def test_coverage_mode_change_is_not_equivalent():
    baseline = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/123456"),
        [],
        modes={"browser": True, "auth_contexts": 2},
    )
    current = build_scan_snapshot(
        _crawl("http://localhost:8000/orders/123456"),
        [],
        modes={"browser": False, "auth_contexts": 0},
    )

    diff = diff_snapshots(baseline, current)

    assert diff["coverage"]["equivalent"] is False
