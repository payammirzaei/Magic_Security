from magic_security.fingerprints import (
    deduplicate_findings,
    response_fingerprint,
)
from magic_security.models import (
    Finding,
    FindingKind,
    PageSnapshot,
    Severity,
)


def _page(url: str, body: str) -> PageSnapshot:
    return PageSnapshot(
        url=url,
        status_code=200,
        headers={"content-type": "text/html"},
        set_cookies=[],
        content_type="text/html; charset=utf-8",
        body=body,
    )


def test_response_fingerprint_ignores_long_volatile_numbers():
    first = response_fingerprint(
        _page("http://localhost/a", "<h1>Order 12345678</h1>")
    )
    second = response_fingerprint(
        _page("http://localhost/b", "<h1>Order 87654321</h1>")
    )
    assert first == second


def test_response_fingerprint_changes_for_different_content():
    first = response_fingerprint(_page("http://localhost/a", "<h1>Hello</h1>"))
    second = response_fingerprint(_page("http://localhost/b", "<h1>Goodbye</h1>"))
    assert first != second


def test_deduplicate_findings_keeps_affected_urls_and_count():
    common = {
        "title": "Missing content-security-policy",
        "severity": Severity.INFO,
        "kind": FindingKind.HARDENING,
        "description": "Content-Security-Policy is not configured.",
        "evidence": "Response did not contain the content-security-policy header.",
        "remediation": "Add a restrictive CSP appropriate for the application.",
        "confidence": 1.0,
    }
    findings = [
        Finding(url="http://localhost/", **common),
        Finding(url="http://localhost/login", **common),
        Finding(url="http://localhost/profile", **common),
    ]

    result = deduplicate_findings(findings)

    assert len(result) == 1
    assert result[0].occurrences == 3
    assert result[0].affected_urls == (
        "http://localhost/",
        "http://localhost/login",
        "http://localhost/profile",
    )
    assert result[0].fingerprint


def test_deduplicate_does_not_merge_different_root_causes():
    findings = [
        Finding(
            title="Open redirect verified",
            severity=Severity.MEDIUM,
            kind=FindingKind.VULNERABILITY,
            url="http://localhost/go?next=/",
            description="The 'next' parameter can redirect externally.",
            evidence="302",
            remediation="Validate redirect destinations.",
            confidence=1.0,
            cwe="CWE-601",
        ),
        Finding(
            title="Open redirect verified",
            severity=Severity.MEDIUM,
            kind=FindingKind.VULNERABILITY,
            url="http://localhost/back?return=/",
            description="The 'return' parameter can redirect externally.",
            evidence="302",
            remediation="Validate redirect destinations.",
            confidence=1.0,
            cwe="CWE-601",
        ),
    ]

    assert len(deduplicate_findings(findings)) == 2
