from __future__ import annotations

import json

from magic_security.backtesting import build_scan_snapshot
from magic_security.models import (
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.redaction import Redactor
from magic_security.reporting import build_report


SEED_SECRETS = [
    "SuperSecretPassword123!",
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb",
    "sk_live_abcdefghijklmnopqrstuv",
    "user@example.com",
    "+1-555-0100",
    "reset-token-ABCDEF123456",
    "otp-998877",
]


def test_redactor_scrubs_headers_cookies_query_json_and_text():
    redactor = Redactor()
    headers = redactor.redact_headers(
        {
            "Authorization": "Bearer abc.def.ghi",
            "X-Api-Key": "sk_live_abcdefghijklmnopqrstuv",
            "Content-Type": "application/json",
        }
    )
    assert "Bearer abc.def.ghi" not in headers["Authorization"]
    assert "sk_live" not in headers["X-Api-Key"]
    assert headers["Content-Type"] == "application/json"

    cookies = redactor.redact_cookies({"session": "raw-session-value"})
    assert "raw-session-value" not in cookies["session"]

    url = redactor.redact_url(
        "https://app.local/reset?token=reset-token-ABCDEF123456&q=ok"
    )
    assert "reset-token-ABCDEF123456" not in url
    assert "q=ok" in url

    payload = redactor.redact_json(
        {"password": "SuperSecretPassword123!", "name": "Ada"}
    )
    assert payload["name"] == "Ada"
    assert "SuperSecretPassword123!" not in payload["password"]

    text = redactor.redact_text(
        "token=reset-token-ABCDEF123456 Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb"
    )
    assert "reset-token-ABCDEF123456" not in text or "[secret:" in text
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb" not in text


def test_report_and_snapshot_never_contain_seeded_secrets():
    crawl = CrawlResult(target="http://127.0.0.1:8000")
    evidence = (
        "password=SuperSecretPassword123! "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb "
        "api_key=sk_live_abcdefghijklmnopqrstuv "
        "email=user@example.com phone=+1-555-0100 "
        "reset_token=reset-token-ABCDEF123456 otp=otp-998877"
    )
    findings = [
        Finding(
            title="Seeded secret finding",
            severity=Severity.HIGH,
            kind=FindingKind.EXPOSURE,
            url="http://127.0.0.1:8000/leak?token=reset-token-ABCDEF123456",
            description=evidence,
            evidence=evidence,
            remediation="redact",
            confidence=1.0,
            check_id="test.seeded.secret",
        )
    ]

    report = build_report(crawl, findings)
    snapshot = build_scan_snapshot(crawl, findings)
    encoded = json.dumps(report) + json.dumps(snapshot)

    for secret in SEED_SECRETS:
        assert secret not in encoded, f"secret leaked: {secret}"
