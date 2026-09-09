"""API Security Pack v1 (STEP 24) — read-only / safe-active only."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from magic_security.auth import map_auth_boundaries
from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import (
    AuthComparison,
    AuthContext,
    CrawlResult,
    EndpointCandidate,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    Severity,
)
from magic_security.transport import SecureTransport


@dataclass
class ApiPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)


def _path_key(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.path.rstrip('/') or '/'}"


def _openapi_paths(endpoints: set[EndpointCandidate] | list[EndpointCandidate]) -> set[str]:
    return {
        _path_key(item.url)
        for item in endpoints
        if getattr(item, "source", "") == "openapi"
    }


def _observed_paths(endpoints: list[NormalizedEndpoint]) -> set[str]:
    return {_path_key(item.url) for item in endpoints}


def _find_undocumented_public(
    crawl: CrawlResult,
) -> list[Finding]:
    openapi = _openapi_paths(crawl.endpoints)
    if not openapi:
        return []

    findings: list[Finding] = []
    for endpoint in crawl.normalized_endpoints:
        if endpoint.method.upper() != "GET":
            continue
        path = _path_key(endpoint.url)
        if path in openapi:
            continue
        if not any(
            token in path.lower()
            for token in ("/api/", "/v1/", "/v2/", "/graphql")
        ):
            continue
        finding = Finding(
            title="Public route observed outside OpenAPI document",
            severity=Severity.LOW,
            kind=FindingKind.EXPOSURE,
            url=endpoint.url,
            description=(
                "A crawl-discovered API-looking route is not present in the "
                "OpenAPI/Swagger document discovered for this target."
            ),
            evidence=(
                f"Observed path {path} was not among OpenAPI paths "
                f"({len(openapi)} documented)."
            ),
            remediation=(
                "Document public routes or restrict undocumented endpoints."
            ),
            confidence=0.85,
            check_id="api.undocumented.public",
        )
        attach_evidence(
            finding,
            EvidenceObject(
                check_id="api.undocumented.public",
                proof_type="openapi_vs_crawl_diff",
                baseline_summary="OpenAPI documents expected public surface",
                mutation_summary="Compared crawl-discovered routes to OpenAPI",
                observed_result=finding.evidence,
                confidence="likely",
                sensitive_values_stored=False,
            ),
        )
        findings.append(finding)
    return findings[:15]


def _auth_inconsistency_findings(
    comparisons: list[AuthComparison],
) -> list[Finding]:
    findings: list[Finding] = []
    for item in comparisons:
        anonymous_ok = (
            item.anonymous_status is not None
            and 200 <= item.anonymous_status < 300
        )
        if item.boundary == "ambiguous":
            pass
        elif item.boundary == "protected" and anonymous_ok:
            pass
        else:
            continue
        finding = Finding(
            title="Anonymous vs authenticated status inconsistency",
            severity=Severity.MEDIUM,
            kind=FindingKind.EXPOSURE,
            url=item.url,
            description=(
                "Endpoint responses differ inconsistently between anonymous "
                "and authenticated contexts, suggesting unclear auth gates."
            ),
            evidence=(
                f"boundary={item.boundary}; anonymous_status="
                f"{item.anonymous_status}; contexts={item.context_statuses}"
            ),
            remediation=(
                "Normalize authorization responses and enforce consistent "
                "anonymous denial for protected resources."
            ),
            confidence=0.9,
            check_id="api.auth.inconsistency",
        )
        attach_evidence(
            finding,
            EvidenceObject(
                check_id="api.auth.inconsistency",
                proof_type="auth_boundary_inconsistency",
                baseline_summary="Protected APIs should deny anonymous access",
                mutation_summary="Compared anonymous vs auth status codes",
                observed_result=finding.evidence,
                confidence="strong",
                sensitive_values_stored=False,
            ),
        )
        findings.append(finding)
    return findings[:20]


async def _unexpected_methods(
    target: str,
    endpoints: list[NormalizedEndpoint],
) -> list[Finding]:
    findings: list[Finding] = []
    samples = [
        ep
        for ep in endpoints
        if ep.method.upper() == "GET"
        and "{" not in ep.url
        and "/api/" in ep.url.lower()
    ][:10]
    async with SecureTransport(follow_redirects=False, timeout=5.0) as client:
        for endpoint in samples:
            try:
                response = await client.request("OPTIONS", endpoint.url)
            except httpx.HTTPError:
                continue
            allow = response.headers.get("allow", "") or response.headers.get(
                "access-control-allow-methods", ""
            )
            unusual = [
                method.strip().upper()
                for method in allow.split(",")
                if method.strip().upper()
                in {"TRACE", "CONNECT", "TRACK"}
            ]
            if not unusual:
                continue
            finding = Finding(
                title="API advertises unexpected HTTP methods",
                severity=Severity.LOW,
                kind=FindingKind.HARDENING,
                url=endpoint.url,
                description="OPTIONS advertised uncommon/dangerous methods.",
                evidence=f"Allow/ACAM included: {', '.join(unusual)}",
                remediation="Disable unused methods on API endpoints.",
                confidence=0.85,
                check_id="api.methods.unexpected",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="api.methods.unexpected",
                    proof_type="options_method_advertisement",
                    baseline_summary="APIs should not advertise TRACE/CONNECT",
                    mutation_summary="Bounded OPTIONS probe",
                    observed_result=finding.evidence,
                    confidence="likely",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    return findings


async def _content_type_confusion(
    endpoints: list[NormalizedEndpoint],
) -> list[Finding]:
    findings: list[Finding] = []
    samples = [
        ep
        for ep in endpoints
        if ep.method.upper() == "GET"
        and "{" not in ep.url
        and "/api/" in ep.url.lower()
    ][:8]
    async with SecureTransport(follow_redirects=False, timeout=5.0) as client:
        for endpoint in samples:
            try:
                json_resp = await client.get(
                    endpoint.url,
                    headers={"Accept": "application/json"},
                )
                xml_resp = await client.get(
                    endpoint.url,
                    headers={"Accept": "application/xml"},
                )
            except httpx.HTTPError:
                continue
            json_ct = json_resp.headers.get("content-type", "")
            xml_ct = xml_resp.headers.get("content-type", "")
            if (
                json_resp.status_code == xml_resp.status_code == 200
                and "json" in json_ct.lower()
                and "xml" in xml_ct.lower()
            ):
                finding = Finding(
                    title="Content-Type negotiation variance observed",
                    severity=Severity.INFO,
                    kind=FindingKind.HARDENING,
                    url=endpoint.url,
                    description=(
                        "Endpoint returned different content types for "
                        "Accept variants without body mutation."
                    ),
                    evidence=(
                        f"Accept json→{json_ct}; Accept xml→{xml_ct}"
                    ),
                    remediation=(
                        "Ensure parsers enforce an explicit content-type "
                        "policy for state-changing operations."
                    ),
                    confidence=0.7,
                    check_id="api.content-type.confusion",
                )
                attach_evidence(
                    finding,
                    EvidenceObject(
                        check_id="api.content-type.confusion",
                        proof_type="accept_variant_observation",
                        baseline_summary="Observed Accept: application/json",
                        mutation_summary="Retried with Accept: application/xml",
                        observed_result=finding.evidence,
                        confidence="candidate",
                        sensitive_values_stored=False,
                    ),
                )
                findings.append(finding)
    return findings


async def _verbose_validation_errors(
    endpoints: list[NormalizedEndpoint],
) -> list[Finding]:
    findings: list[Finding] = []
    samples = [
        ep
        for ep in endpoints
        if ep.method.upper() == "GET"
        and ep.parameters
        and "{" not in ep.url
    ][:10]
    async with SecureTransport(follow_redirects=False, timeout=5.0) as client:
        for endpoint in samples:
            parameter = endpoint.parameters[0]
            parts = urlsplit(endpoint.url)
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            query[parameter] = '{"$gt":""}'
            probe_url = urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(query),
                    "",
                )
            )
            try:
                response = await client.get(probe_url)
            except httpx.HTTPError:
                continue
            body = response.text[:2000].lower()
            if not any(
                token in body
                for token in (
                    "traceback",
                    "exception",
                    "stack",
                    "validationerror",
                    "typeerror",
                    "cast to",
                )
            ):
                continue
            finding = Finding(
                title="Verbose validation/type error details exposed",
                severity=Severity.LOW,
                kind=FindingKind.EXPOSURE,
                url=endpoint.url,
                description=(
                    "A harmless bad-type probe elicited verbose validation "
                    "or exception details."
                ),
                evidence=(
                    f"HTTP {response.status_code}; body length="
                    f"{len(response.content)}; detailed error tokens present. "
                    "Body not stored."
                ),
                remediation="Return generic validation errors in production.",
                confidence=0.9,
                check_id="api.validation.verbose",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="api.validation.verbose",
                    proof_type="harmless_bad_type_probe",
                    baseline_summary="Normal typed parameter expected",
                    mutation_summary="Injected inert bad-type marker",
                    observed_result=finding.evidence,
                    confidence="strong",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    return findings


async def _pagination_boundary(
    endpoints: list[NormalizedEndpoint],
) -> list[Finding]:
    findings: list[Finding] = []
    samples = [
        ep
        for ep in endpoints
        if ep.method.upper() == "GET"
        and "{" not in ep.url
        and any(
            name.lower() in {"limit", "offset", "page", "per_page", "page_size"}
            for name in ep.parameters
        )
    ][:6]
    async with SecureTransport(follow_redirects=False, timeout=5.0) as client:
        for endpoint in samples:
            parts = urlsplit(endpoint.url)
            query = dict(parse_qsl(parts.query, keep_blank_values=True))
            for key in ("limit", "page_size", "per_page"):
                if key in {p.lower() for p in endpoint.parameters} or key in {
                    k.lower() for k in query
                }:
                    query[key] = "100000"
            probe_url = urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(query),
                    "",
                )
            )
            try:
                response = await client.get(probe_url)
            except httpx.HTTPError:
                continue
            if response.status_code != 200:
                continue
            if len(response.content) < 50_000:
                continue
            finding = Finding(
                title="Large pagination limit accepted",
                severity=Severity.INFO,
                kind=FindingKind.HARDENING,
                url=endpoint.url,
                description=(
                    "Endpoint accepted an extreme pagination limit and "
                    "returned a large response."
                ),
                evidence=(
                    f"HTTP 200; response_bytes={len(response.content)} "
                    "(capped observation; body not stored)."
                ),
                remediation="Cap pagination limits server-side.",
                confidence=0.8,
                check_id="api.pagination.boundary",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="api.pagination.boundary",
                    proof_type="pagination_extreme_limit",
                    baseline_summary="Default page size expected",
                    mutation_summary="Requested capped extreme limit/offset",
                    observed_result=finding.evidence,
                    confidence="likely",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    return findings


def _versioned_path_hints(endpoints: list[NormalizedEndpoint]) -> list[Finding]:
    paths = {_path_key(ep.url) for ep in endpoints}
    findings: list[Finding] = []
    for path in sorted(paths):
        if "/v1/" not in path.lower():
            continue
        v2 = path.lower().replace("/v1/", "/v2/")
        # Rebuild matching path case-insensitively from set.
        matches = [p for p in paths if p.lower() == v2]
        if not matches:
            continue
        finding = Finding(
            title="Historical and current API versions both exposed",
            severity=Severity.INFO,
            kind=FindingKind.HARDENING,
            url=path,
            description="Both /v1 and /v2 style routes were observed.",
            evidence=f"Saw {path} and {matches[0]}",
            remediation=(
                "Retire unused historical versions or isolate them."
            ),
            confidence=0.75,
            check_id="api.version.historical",
        )
        attach_evidence(
            finding,
            EvidenceObject(
                check_id="api.version.historical",
                proof_type="version_path_coexistence",
                baseline_summary="Historical version paths noted",
                mutation_summary="Passive path comparison only",
                observed_result=finding.evidence,
                confidence="candidate",
                sensitive_values_stored=False,
            ),
        )
        findings.append(finding)
        if len(findings) >= 5:
            break
    return findings


async def run_api_security_pack(
    crawl: CrawlResult,
    *,
    active: bool = False,
    auth_contexts: list[AuthContext] | None = None,
    auth_comparisons: list[AuthComparison] | None = None,
) -> ApiPackResult:
    result = ApiPackResult()
    exercised: list[str] = []
    skipped: list[str] = []
    findings: list[Finding] = []

    undocumented = _find_undocumented_public(crawl)
    findings.extend(undocumented)
    exercised.append("openapi_vs_observed")

    comparisons = list(auth_comparisons or crawl.auth_comparisons)
    if auth_contexts and not comparisons:
        comparisons = await map_auth_boundaries(
            crawl.normalized_endpoints,
            auth_contexts,
        )
        crawl.auth_comparisons = comparisons
    if comparisons:
        findings.extend(_auth_inconsistency_findings(comparisons))
        exercised.append("auth_inconsistency")
    else:
        skipped.append("auth_inconsistency")

    if active:
        findings.extend(
            await _unexpected_methods(crawl.target, crawl.normalized_endpoints)
        )
        exercised.append("unexpected_methods")
        findings.extend(
            await _content_type_confusion(crawl.normalized_endpoints)
        )
        exercised.append("content_type_confusion")
        findings.extend(
            await _verbose_validation_errors(crawl.normalized_endpoints)
        )
        exercised.append("verbose_validation")
        findings.extend(
            await _pagination_boundary(crawl.normalized_endpoints)
        )
        exercised.append("pagination_boundary")
    else:
        skipped.extend(
            [
                "unexpected_methods",
                "content_type_confusion",
                "verbose_validation",
                "pagination_boundary",
            ]
        )

    findings.extend(_versioned_path_hints(crawl.normalized_endpoints))
    exercised.append("version_hints")

    # Mass-assignment requires workflows (STEP 31+).
    skipped.append("mass_assignment")
    mass_finding = Finding(
        title="Mass-assignment checks require workflow configuration",
        severity=Severity.INFO,
        kind=FindingKind.HARDENING,
        url=crawl.target,
        description=(
            "Mass-assignment verification is registered but skipped until "
            "declarative workflows are configured."
        ),
        evidence="Requires Config / workflow prerequisite missing.",
        remediation="Configure write workflows when available (STEP 31+).",
        confidence=0.4,
        check_id="api.mass-assignment.skipped",
    )
    attach_evidence(
        mass_finding,
        EvidenceObject(
            check_id="api.mass-assignment.skipped",
            proof_type="requires_config",
            baseline_summary="Mass-assignment not exercised",
            mutation_summary="Skipped without workflow",
            observed_result="skipped",
            confidence="candidate",
            sensitive_values_stored=False,
        ),
    )
    # Do not emit as a finding row that looks like a vulnerability — coverage only.
    # Keep skipped marker in coverage, not findings list.
    del mass_finding

    result.findings = findings
    result.skipped = skipped
    result.coverage = {
        "pack": "api_v1",
        "exercised": exercised,
        "skipped": skipped,
        "findings": len(findings),
        "mass_assignment": "requires_config",
    }
    return result
