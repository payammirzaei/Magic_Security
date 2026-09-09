from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from magic_security.transport import open_secure_transport

from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import EndpointCandidate, Finding, FindingKind, Severity


_PROBE_ORIGIN = "https://magic-security.invalid"
_REDIRECT_DESTINATION = "https://magic-security.invalid/verified-redirect"
_REDIRECT_PARAMETERS = {
    "next",
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_to",
    "return_url",
    "continue",
    "dest",
    "destination",
    "callback",
}


def _replace_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []

    for key, current in query:
        if key == parameter:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, current))

    if not replaced:
        updated.append((parameter, value))

    return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))


def _redirect_parameter_names(endpoint: EndpointCandidate) -> set[str]:
    names = {name.lower() for name in endpoint.parameters}
    return names & _REDIRECT_PARAMETERS


async def verify_cors(
    urls: Iterable[str],
    *,
    timeout: float = 5.0,
    max_urls: int = 30,
) -> list[Finding]:
    """Verify arbitrary-origin reflection.

    This intentionally reports the issue as an exposure rather than claiming
    sensitive-data theft. Authenticated impact needs a future test-account mode.
    """

    findings: list[Finding] = []
    seen: set[str] = set()

    async with open_secure_transport(follow_redirects=False, timeout=timeout) as client:
        for url in sorted(set(urls))[:max_urls]:
            try:
                response = await client.get(
                    url,
                    headers={
                        "Origin": _PROBE_ORIGIN,
                        "User-Agent": "Magic-Security/0.3 local-security-scanner",
                    },
                )
            except httpx.HTTPError:
                continue

            allow_origin = response.headers.get("access-control-allow-origin", "").strip()
            allow_credentials = response.headers.get(
                "access-control-allow-credentials", ""
            ).strip().lower()

            if allow_origin != _PROBE_ORIGIN:
                continue

            key = f"{url}|{allow_credentials}"
            if key in seen:
                continue
            seen.add(key)

            credentialed = allow_credentials == "true"
            finding = Finding(
                title=(
                    "Arbitrary CORS origin accepted with credentials"
                    if credentialed
                    else "Arbitrary CORS origin is reflected"
                ),
                severity=Severity.HIGH if credentialed else Severity.MEDIUM,
                kind=FindingKind.EXPOSURE,
                url=url,
                description=(
                    "The server reflected an untrusted Origin and explicitly allows credentials."
                    if credentialed
                    else "The server reflected an arbitrary untrusted Origin in its CORS policy."
                ),
                evidence=(
                    f"Request Origin {_PROBE_ORIGIN!r} was reflected as "
                    f"Access-Control-Allow-Origin. "
                    f"Access-Control-Allow-Credentials={allow_credentials or 'absent'}."
                ),
                remediation=(
                    "Use an explicit allowlist of trusted origins and only enable credentials where required."
                ),
                confidence=1.0,
                owasp="A02:2025 Security Misconfiguration",
                cwe="CWE-942",
                check_id="cors.arbitrary-origin",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="cors.arbitrary-origin",
                    proof_type="reflected_acao_origin",
                    baseline_summary="Trusted CORS allowlist expected",
                    mutation_summary=f"Sent Origin {_PROBE_ORIGIN}",
                    observed_result=finding.evidence,
                    confidence="verified",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)

    return findings


async def verify_open_redirects(
    endpoints: Iterable[EndpointCandidate],
    *,
    timeout: float = 5.0,
    max_tests: int = 30,
) -> list[Finding]:
    """Confirm server-side open redirects using only redirect-like parameters."""

    findings: list[Finding] = []
    tested = 0
    reported: set[tuple[str, str]] = set()

    async with open_secure_transport(follow_redirects=False, timeout=timeout) as client:
        for endpoint in sorted(
            set(endpoints),
            key=lambda item: (item.url, item.method, item.source),
        ):
            if tested >= max_tests:
                break
            if endpoint.method.upper() != "GET":
                continue
            if "{" in endpoint.url or "}" in endpoint.url:
                continue

            candidate_parameters = _redirect_parameter_names(endpoint)
            if not candidate_parameters:
                continue

            for parameter in sorted(candidate_parameters):
                if tested >= max_tests:
                    break
                tested += 1

                probe_url = _replace_query_parameter(
                    endpoint.url,
                    parameter,
                    _REDIRECT_DESTINATION,
                )
                try:
                    response = await client.get(
                        probe_url,
                        headers={
                            "User-Agent": "Magic-Security/0.3 local-security-scanner"
                        },
                    )
                except httpx.HTTPError:
                    continue

                if response.status_code not in {301, 302, 303, 307, 308}:
                    continue

                location = response.headers.get("location", "").strip()
                if not location.startswith(_REDIRECT_DESTINATION):
                    continue

                report_key = (endpoint.url, parameter)
                if report_key in reported:
                    continue
                reported.add(report_key)

                findings.append(
                    Finding(
                        title="Open redirect verified",
                        severity=Severity.MEDIUM,
                        kind=FindingKind.VULNERABILITY,
                        url=endpoint.url,
                        description=(
                            f"The {parameter!r} parameter can redirect a visitor to an arbitrary external origin."
                        ),
                        evidence=(
                            f"A controlled request set {parameter!r} to "
                            f"{_REDIRECT_DESTINATION!r}; the server returned HTTP "
                            f"{response.status_code} with Location={location!r}."
                        ),
                        remediation=(
                            "Allow only relative paths or validate redirect destinations against an explicit allowlist."
                        ),
                        confidence=1.0,
                        owasp="A01:2025 Broken Access Control",
                        cwe="CWE-601",
                    )
                )

    return findings


async def run_safe_active_checks(
    *,
    page_urls: Iterable[str],
    endpoints: Iterable[EndpointCandidate],
) -> list[Finding]:
    """Run the intentionally small, non-destructive active-check set."""

    endpoints = set(endpoints)
    cors_urls = set(page_urls)
    cors_urls.update(
        endpoint.url
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    )

    findings: list[Finding] = []
    findings.extend(await verify_cors(cors_urls))
    findings.extend(await verify_open_redirects(endpoints))
    return findings
