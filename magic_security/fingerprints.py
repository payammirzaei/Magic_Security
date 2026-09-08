from __future__ import annotations

import hashlib
import re
from dataclasses import replace

from magic_security.models import Finding, PageSnapshot, Severity


_WHITESPACE_RE = re.compile(r"\s+")
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_LONG_NUMBER_RE = re.compile(r"\b\d{6,}\b")

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def normalize_response_body(body: str) -> str:
    body = body[:500_000]
    body = _UUID_RE.sub("<uuid>", body)
    body = _LONG_NUMBER_RE.sub("<number>", body)
    return _WHITESPACE_RE.sub(" ", body).strip()


def response_fingerprint(page: PageSnapshot) -> str:
    content_type = page.content_type.split(";", 1)[0].strip().lower()
    payload = "\n".join(
        [
            str(page.status_code),
            content_type,
            normalize_response_body(page.body),
        ]
    ).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()[:16]


def group_response_fingerprints(
    pages: list[PageSnapshot],
) -> dict[str, tuple[str, ...]]:
    groups: dict[str, set[str]] = {}
    for page in pages:
        fingerprint = response_fingerprint(page)
        groups.setdefault(fingerprint, set()).add(page.url)

    return {
        fingerprint: tuple(sorted(urls))
        for fingerprint, urls in sorted(groups.items())
    }


def finding_root_fingerprint(finding: Finding) -> str:
    payload = "\n".join(
        [
            finding.kind.value,
            finding.title.strip().lower(),
            finding.description.strip().lower(),
            finding.remediation.strip().lower(),
            (finding.cwe or "").strip().lower(),
            (finding.owasp or "").strip().lower(),
        ]
    ).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()[:16]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[str, Finding] = {}
    urls: dict[str, set[str]] = {}
    occurrences: dict[str, int] = {}

    for finding in findings:
        fingerprint = finding_root_fingerprint(finding)
        occurrences[fingerprint] = occurrences.get(fingerprint, 0) + 1
        urls.setdefault(fingerprint, set()).add(finding.url)

        current = grouped.get(fingerprint)
        if current is None:
            grouped[fingerprint] = replace(
                finding,
                fingerprint=fingerprint,
            )
            continue

        better_severity = (
            finding.severity
            if _SEVERITY_RANK[finding.severity] > _SEVERITY_RANK[current.severity]
            else current.severity
        )
        better_confidence = max(current.confidence, finding.confidence)

        grouped[fingerprint] = replace(
            current,
            severity=better_severity,
            confidence=better_confidence,
        )

    result: list[Finding] = []
    for fingerprint, finding in grouped.items():
        affected = tuple(sorted(urls[fingerprint]))
        result.append(
            replace(
                finding,
                affected_urls=affected,
                occurrences=occurrences[fingerprint],
                fingerprint=fingerprint,
            )
        )

    return result
