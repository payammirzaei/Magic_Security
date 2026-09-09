from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from magic_security.transport import open_secure_transport

from magic_security.models import (
    Finding,
    FindingKind,
    NormalizedEndpoint,
    ParameterSecurityObservation,
    Severity,
)


_SQL_ERRORS = (
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"pg_query\(", re.I),
    re.compile(r"sqlite(?:3)?\.(?:operationalerror|databaseerror)", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"sqlstate\[[0-9a-z]+\]", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
)


def _set_query(
    url: str,
    parameter: str,
    value: str,
    *,
    duplicate: bool = False,
) -> str:
    parts = urlsplit(url)
    pairs = [
        (key, current)
        for key, current in parse_qsl(parts.query, keep_blank_values=True)
        if key != parameter
    ]
    pairs.append((parameter, value))
    if duplicate:
        pairs.append((parameter, value + "-second"))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(pairs, doseq=True),
            parts.fragment,
        )
    )


def _fingerprint(response: httpx.Response) -> str:
    body = response.content[:500_000]
    payload = (
        str(response.status_code).encode()
        + b"\n"
        + response.headers.get("content-type", "").encode()
        + b"\n"
        + body
    )
    return hashlib.sha256(payload).hexdigest()[:16]


def _sql_signature(body: str) -> str | None:
    for pattern in _SQL_ERRORS:
        match = pattern.search(body)
        if match:
            return match.group(0)[:80]
    return None


async def verify_parameter_security(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_tests: int = 40,
) -> tuple[list[ParameterSecurityObservation], list[Finding]]:
    observations: list[ParameterSecurityObservation] = []
    findings: list[Finding] = []
    tested = 0

    candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
        and endpoint.parameters
    ]

    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.9 local-security-scanner",
        },
    ) as client:
        for endpoint in candidates:
            for parameter in endpoint.parameters:
                if tested >= max_tests:
                    return observations, findings
                tested += 1

                baseline_url = _set_query(
                    endpoint.url,
                    parameter,
                    "magic-security-baseline",
                )
                try:
                    baseline = await client.get(baseline_url)
                except httpx.HTTPError:
                    continue

                baseline_body = baseline.text[:500_000]
                baseline_fp = _fingerprint(baseline)

                # 1) Error-based database behavior. This is evidence of unsafe
                # backend error handling, not automatically proof of SQL injection.
                sql_url = _set_query(
                    endpoint.url,
                    parameter,
                    "magic-security-'",
                )
                try:
                    sql_response = await client.get(sql_url)
                except httpx.HTTPError:
                    sql_response = None

                if sql_response is not None:
                    signature = _sql_signature(sql_response.text[:500_000])
                    baseline_signature = _sql_signature(baseline_body)
                    triggered = bool(signature and not baseline_signature)

                    observations.append(
                        ParameterSecurityObservation(
                            url=endpoint.url,
                            parameter=parameter,
                            category="database_error",
                            verified=triggered,
                            detail=(
                                "database error signature triggered"
                                if triggered
                                else "no new database error signature"
                            ),
                        )
                    )

                    if triggered:
                        findings.append(
                            Finding(
                                title="Input triggers a database error response",
                                severity=Severity.MEDIUM,
                                kind=FindingKind.EXPOSURE,
                                url=endpoint.url,
                                description=(
                                    "A controlled query mutation caused a database-specific "
                                    "error signature that was absent from the baseline."
                                ),
                                evidence=(
                                    f"Parameter {parameter!r} triggered a database error "
                                    "signature after an apostrophe probe. The response body "
                                    "and database details were not retained."
                                ),
                                remediation=(
                                    "Use parameterized queries and generic production error "
                                    "handling. Review this endpoint manually for SQL injection."
                                ),
                                confidence=1.0,
                                cwe="CWE-209",
                            )
                        )

                # 2) SSTI arithmetic evaluation.
                ssti_marker = "9359"
                ssti_url = _set_query(
                    endpoint.url,
                    parameter,
                    "{{1337*7}}",
                )
                try:
                    ssti_response = await client.get(ssti_url)
                except httpx.HTTPError:
                    ssti_response = None

                if ssti_response is not None:
                    body = ssti_response.text[:500_000]
                    evaluated = (
                        ssti_marker in body
                        and ssti_marker not in baseline_body
                        and "{{1337*7}}" not in body
                    )
                    observations.append(
                        ParameterSecurityObservation(
                            url=endpoint.url,
                            parameter=parameter,
                            category="ssti",
                            verified=evaluated,
                            detail=(
                                "template arithmetic evaluated"
                                if evaluated
                                else "no template evaluation observed"
                            ),
                        )
                    )

                    if evaluated:
                        findings.append(
                            Finding(
                                title="Server-side template injection verified",
                                severity=Severity.HIGH,
                                kind=FindingKind.VULNERABILITY,
                                url=endpoint.url,
                                description=(
                                    "A harmless arithmetic template expression was evaluated "
                                    "server-side and its computed result appeared in the response."
                                ),
                                evidence=(
                                    f"Parameter {parameter!r} evaluated the scanner's "
                                    "arithmetic-only template canary. No file, process, network, "
                                    "or environment access was attempted."
                                ),
                                remediation=(
                                    "Never render untrusted input as a template. Pass user values "
                                    "as data and use sandboxed template configuration where available."
                                ),
                                confidence=1.0,
                                cwe="CWE-1336",
                            )
                        )

                # 3) CRLF response-header injection.
                header_name = "x-magic-security-probe"
                crlf_url = _set_query(
                    endpoint.url,
                    parameter,
                    "probe\r\nX-Magic-Security-Probe: verified",
                )
                try:
                    crlf_response = await client.get(crlf_url)
                except httpx.HTTPError:
                    crlf_response = None

                if crlf_response is not None:
                    injected = (
                        crlf_response.headers.get(header_name, "").lower()
                        == "verified"
                    )
                    observations.append(
                        ParameterSecurityObservation(
                            url=endpoint.url,
                            parameter=parameter,
                            category="crlf_header_injection",
                            verified=injected,
                            detail=(
                                "controlled response header injected"
                                if injected
                                else "no response-header injection observed"
                            ),
                        )
                    )

                    if injected:
                        findings.append(
                            Finding(
                                title="HTTP response header injection verified",
                                severity=Severity.HIGH,
                                kind=FindingKind.VULNERABILITY,
                                url=endpoint.url,
                                description=(
                                    "A query parameter injected a new HTTP response header."
                                ),
                                evidence=(
                                    f"Parameter {parameter!r} caused the inert scanner header "
                                    "X-Magic-Security-Probe: verified to appear in the response."
                                ),
                                remediation=(
                                    "Reject CR/LF characters in header-derived input and use "
                                    "framework header APIs that prevent response splitting."
                                ),
                                confidence=1.0,
                                cwe="CWE-113",
                            )
                        )

                # 4) HTTP parameter pollution behavior. This remains an observation,
                # because differing duplicate-parameter semantics are not themselves a bug.
                hpp_url = _set_query(
                    endpoint.url,
                    parameter,
                    "magic-security-first",
                    duplicate=True,
                )
                try:
                    hpp_response = await client.get(hpp_url)
                except httpx.HTTPError:
                    hpp_response = None

                if hpp_response is not None:
                    changed = _fingerprint(hpp_response) != baseline_fp
                    observations.append(
                        ParameterSecurityObservation(
                            url=endpoint.url,
                            parameter=parameter,
                            category="parameter_pollution",
                            verified=False,
                            detail=(
                                "duplicate parameter changed response behavior"
                                if changed
                                else "duplicate parameter matched baseline behavior"
                            ),
                        )
                    )

    return observations, findings
