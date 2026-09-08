from magic_security.checks.cookies import CookieSecurityCheck
from magic_security.checks.exposures import ExposureHeuristicCheck
from magic_security.checks.headers import SecurityHeaderCheck
from magic_security.models import FindingKind, PageSnapshot


def page(**overrides):
    data = {
        "url": "http://localhost:8000/",
        "status_code": 200,
        "headers": {"content-type": "text/html"},
        "set_cookies": [],
        "content_type": "text/html",
        "body": "<html><body>ok</body></html>",
    }
    data.update(overrides)
    return PageSnapshot(**data)


def test_missing_headers_are_hardening_not_vulnerabilities():
    findings = SecurityHeaderCheck().run(page())
    assert findings
    assert all(item.kind is FindingKind.HARDENING for item in findings)


def test_cookie_value_is_not_leaked_into_evidence():
    findings = CookieSecurityCheck().run(
        page(set_cookies=["session=super-secret-value; Path=/"])
    )
    assert len(findings) == 1
    assert "super-secret-value" not in findings[0].evidence
    assert "session" in findings[0].evidence


def test_directory_listing_is_exposure():
    findings = ExposureHeuristicCheck().run(
        page(body="<html><title>Index of /uploads</title></html>")
    )
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.EXPOSURE
    assert findings[0].verified
