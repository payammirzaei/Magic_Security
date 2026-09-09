from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from magic_security.models import Finding, FindingKind, PageSnapshot, Severity


_WHITESPACE_RE = re.compile(r"\s+")
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_LONG_NUMBER_RE = re.compile(r"\b\d{6,}\b")
_OBJECT_ID_RE = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)
_NUMERIC_SEGMENT_RE = re.compile(r"^\d{3,}$")

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_CHECK_ID_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^missing (.+)$", re.IGNORECASE), "hardening.header.missing"),
    (re.compile(r"^page lacks clickjacking", re.IGNORECASE), "browser.clickjacking.missing-protection"),
    (re.compile(r"^csp allows risky", re.IGNORECASE), "browser.csp.risky-script-mode"),
    (re.compile(r"^cookie .+ is missing security attributes$", re.IGNORECASE), "session.cookie.missing-attributes"),
    (re.compile(r"^session-like cookie .+ lacks protective attributes$", re.IGNORECASE), "session.cookie.missing-attributes"),
    (re.compile(r"^directory listing is enabled$", re.IGNORECASE), "exposure.directory-listing"),
    (re.compile(r"^api documentation is publicly exposed$", re.IGNORECASE), "exposure.api-docs.public"),
    (re.compile(r"^debug or stack-trace information exposed$", re.IGNORECASE), "exposure.debug-output"),
    (re.compile(r"^reflected html injection verified$", re.IGNORECASE), "injection.html.reflected"),
    (re.compile(r"^reflected xss execution verified$", re.IGNORECASE), "xss.reflected.execution"),
    (re.compile(r"^dom-based xss execution verified$", re.IGNORECASE), "xss.dom.execution"),
    (re.compile(r"^potential dom xss", re.IGNORECASE), "xss.dom.candidate"),
    (re.compile(r"^cross-account object access verified", re.IGNORECASE), "authorization.bola.read"),
    (re.compile(r"^path traversal / local file read verified$", re.IGNORECASE), "path.traversal.local-file-read"),
    (re.compile(r"^server-side request forgery verified$", re.IGNORECASE), "ssrf.loopback-callback"),
    (re.compile(r"^sql-style authentication bypass verified$", re.IGNORECASE), "authentication.sqli.bypass"),
    (re.compile(r"^nosql operator authentication bypass verified$", re.IGNORECASE), "authentication.nosqli.bypass"),
    (re.compile(r"^untrusted host header influences response content$", re.IGNORECASE), "http.host-header.influence"),
    (re.compile(r"^credentialed cors policy exposes a protected endpoint$", re.IGNORECASE), "cors.protected.credentialed"),
    (re.compile(r"^arbitrary cors origin", re.IGNORECASE), "cors.arbitrary-origin"),
    (re.compile(r"^cors accepts null origin", re.IGNORECASE), "cors.null-origin"),
    (re.compile(r"^user-specific authenticated response is marked for shared caching$", re.IGNORECASE), "cache.authenticated.shared"),
    (re.compile(r"^anonymous graphql introspection is enabled$", re.IGNORECASE), "graphql.introspection.anonymous"),
    (re.compile(r"^graphql error responses expose debug details$", re.IGNORECASE), "graphql.errors.debug"),
    (re.compile(r"^secret/authentication material appears in url$", re.IGNORECASE), "privacy.url.secret"),
    (re.compile(r"^personal/payment data appears in url$", re.IGNORECASE), "privacy.url.pii"),
    (re.compile(r"^sensitive form fields are submitted with get$", re.IGNORECASE), "privacy.form.get-sensitive"),
    (re.compile(r"^https page references insecure http resources$", re.IGNORECASE), "transport.mixed-content"),
    (re.compile(r"^jsonp-style arbitrary callback wrapping verified$", re.IGNORECASE), "jsonp.callback.arbitrary"),
    (re.compile(r"^open redirect verified$", re.IGNORECASE), "redirect.open"),
    (re.compile(r"^web message handler lacks an obvious origin check$", re.IGNORECASE), "browser.postmessage.origin-check"),
    (re.compile(r"^potential client-side redirect flow$", re.IGNORECASE), "redirect.client.candidate"),
    (re.compile(r"^secure page references plaintext websocket transport$", re.IGNORECASE), "websocket.plaintext-transport"),
    (re.compile(r"^sensitive-looking browser storage key observed$", re.IGNORECASE), "browser.storage.sensitive-key"),
    (re.compile(r"^client artifact exposes secret-like material$", re.IGNORECASE), "client.secret-like-material"),
    (re.compile(r"^client artifact reveals internal network locations$", re.IGNORECASE), "client.internal-topology"),
    (re.compile(r"^sensitive deployment artifact is publicly exposed$", re.IGNORECASE), "exposure.deployment-artifact.public"),
    (re.compile(r"^production debug/status endpoint is exposed$", re.IGNORECASE), "exposure.debug-status.public"),
    (re.compile(r"^spring actuator environment endpoint is exposed$", re.IGNORECASE), "exposure.spring-actuator.env"),
    (re.compile(r"^public configuration exposes secret-like keys$", re.IGNORECASE), "exposure.config.secret-keys"),
    (re.compile(r"^application heap dump endpoint is publicly exposed$", re.IGNORECASE), "exposure.heapdump.public"),
    (re.compile(r"^input triggers a database error response$", re.IGNORECASE), "database.error-trigger"),
    (re.compile(r"^server-side template injection verified$", re.IGNORECASE), "injection.ssti.arithmetic"),
    (re.compile(r"^http response header injection verified$", re.IGNORECASE), "injection.crlf.response-header"),
    (re.compile(r"^environment file is publicly exposed$", re.IGNORECASE), "exposure.env.public"),
    (re.compile(r"^git metadata is publicly exposed$", re.IGNORECASE), "exposure.git.public"),
    (re.compile(r"^openapi specification is publicly exposed$", re.IGNORECASE), "exposure.openapi.public"),
    (re.compile(r"^frontend source map is publicly exposed$", re.IGNORECASE), "exposure.sourcemap.public"),
    (re.compile(r"^.+ reveals server technology$", re.IGNORECASE), "hardening.server-technology-disclosure"),
    (re.compile(r"^http trace method reflects request data$", re.IGNORECASE), "http.trace.reflection"),
    (re.compile(r"^potentially dangerous http methods advertised$", re.IGNORECASE), "http.methods.dangerous-advertised"),
)

_LOCATION_SENSITIVE_PREFIXES = (
    "authentication.",
    "authorization.",
    "cache.",
    "cors.",
    "database.",
    "graphql.",
    "http.host-header.",
    "injection.",
    "jsonp.",
    "path.",
    "privacy.",
    "redirect.",
    "ssrf.",
    "transport.",
    "websocket.",
    "xss.",
)


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


def _slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "unknown"


def finding_check_id(finding: Finding) -> str:
    if finding.check_id:
        return finding.check_id

    title = finding.title.strip()
    for pattern, check_id in _CHECK_ID_PATTERNS:
        match = pattern.match(title)
        if not match:
            continue
        if check_id == "hardening.header.missing":
            return f"{check_id}.{_slug(match.group(1))}"
        return check_id

    legacy_payload = "\n".join(
        [
            finding.kind.value,
            title.lower(),
            (finding.cwe or "").strip().lower(),
            (finding.owasp or "").strip().lower(),
        ]
    ).encode("utf-8", errors="replace")
    return "legacy." + hashlib.sha256(legacy_payload).hexdigest()[:12]


def normalize_finding_url(url: str) -> str:
    parts = urlsplit(url)
    segments: list[str] = []
    for segment in parts.path.split("/"):
        if (
            _UUID_RE.fullmatch(segment)
            or _OBJECT_ID_RE.fullmatch(segment)
            or _NUMERIC_SEGMENT_RE.fullmatch(segment)
        ):
            segments.append("{id}")
        else:
            segments.append(segment)

    query_keys = sorted({key for key, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = urlencode([(key, "") for key in query_keys], doseq=True)
    return urlunsplit(
        (
            parts.scheme.lower(),
            parts.netloc.lower(),
            "/".join(segments) or "/",
            query,
            "",
        )
    )


def _location_sensitive(finding: Finding, check_id: str) -> bool:
    if finding.kind is FindingKind.VULNERABILITY:
        return True
    return check_id.startswith(_LOCATION_SENSITIVE_PREFIXES)


def finding_root_fingerprint(finding: Finding) -> str:
    check_id = finding_check_id(finding)
    payload_parts = [
        "v2",
        check_id,
        finding.kind.value,
        (finding.cwe or "").strip().lower(),
    ]
    if _location_sensitive(finding, check_id):
        payload_parts.append(normalize_finding_url(finding.url))

    payload = "\n".join(payload_parts).encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()[:20]


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[str, Finding] = {}
    urls: dict[str, set[str]] = {}
    occurrences: dict[str, int] = {}

    for finding in findings:
        check_id = finding_check_id(finding)
        fingerprint = finding_root_fingerprint(
            replace(finding, check_id=check_id)
        )
        occurrences[fingerprint] = occurrences.get(fingerprint, 0) + 1
        urls.setdefault(fingerprint, set()).add(finding.url)

        current = grouped.get(fingerprint)
        if current is None:
            grouped[fingerprint] = replace(
                finding,
                check_id=check_id,
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
            check_id=check_id,
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
