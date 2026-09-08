from magic_security.checks.headers import SecurityHeaderCheck
from magic_security.models import FindingKind, PageSnapshot


def _page(headers):
    return PageSnapshot(
        url="http://localhost/",
        status_code=200,
        headers=headers,
        set_cookies=[],
        content_type="text/html",
        body="<html></html>",
    )


def test_missing_frame_protection_is_hardening():
    findings = SecurityHeaderCheck().run(
        _page({"content-type": "text/html"})
    )

    item = next(
        finding
        for finding in findings
        if "clickjacking" in finding.title.lower()
    )
    assert item.kind is FindingKind.HARDENING
    assert item.verified


def test_csp_frame_ancestors_counts_as_frame_protection():
    findings = SecurityHeaderCheck().run(
        _page(
            {
                "content-type": "text/html",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            }
        )
    )

    assert not any(
        "clickjacking" in finding.title.lower()
        for finding in findings
    )
