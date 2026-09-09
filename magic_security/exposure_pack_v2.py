"""External Exposure Pack v2 (STEP 21).

Orchestrates existing exposure/leakage checks with explicit kind tagging
and coverage accounting. Does not rewrite underlying probes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from magic_security.client_artifacts import analyze_client_artifacts
from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.exposure_pack import probe_sensitive_endpoints
from magic_security.index_discovery import discover_index_documents
from magic_security.models import (
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.probes import probe_common_exposures, probe_source_maps
from magic_security.transport import SecureTransport
from magic_security.user_surface_security import analyze_user_visible_surface


_SENSITIVE_INDEX_TOKENS = (
    "admin",
    "backup",
    "config",
    "debug",
    "env",
    "internal",
    "private",
    "secret",
    "staging",
    "phpinfo",
    "actuator",
    ".git",
    ".env",
    "dump",
    "sql",
)


@dataclass
class ExposurePackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    observations: list[dict[str, str]] = field(default_factory=list)


def _ensure_kind_and_evidence(finding: Finding) -> Finding:
    """Normalize kind/severity and attach evidence if missing."""
    if finding.kind is FindingKind.HARDENING and finding.severity in {
        Severity.HIGH,
        Severity.CRITICAL,
    }:
        # STEP 21 DoD: bare hardening must not be high without verified impact.
        finding.severity = Severity.LOW

    if finding.structured_evidence is None:
        proof = "verified_exposure"
        if finding.kind is FindingKind.HARDENING:
            proof = "hardening_observation"
        elif finding.confidence < 0.95:
            proof = "exposure_observation"
        attach_evidence(
            finding,
            EvidenceObject(
                check_id=finding.check_id or "exposure.external",
                proof_type=proof,
                baseline_summary="Resource should not be publicly observable",
                mutation_summary="Passive or bounded GET probe",
                observed_result=finding.evidence,
                confidence=(
                    "verified" if finding.confidence >= 0.95 else "likely"
                ),
                sensitive_values_stored=False,
            ),
        )
    return finding


async def _probe_index_sensitive_paths(
    target: str,
    robots_links: set[str] | list[str] | tuple[str, ...],
) -> list[Finding]:
    findings: list[Finding] = []
    candidates = [
        url
        for url in sorted(robots_links)
        if any(token in url.lower() for token in _SENSITIVE_INDEX_TOKENS)
    ][:20]
    if not candidates:
        return findings

    async with SecureTransport(follow_redirects=False, timeout=5.0) as client:
        for url in candidates:
            try:
                response = await client.get(url)
            except Exception:
                continue
            if response.status_code != 200:
                continue
            finding = Finding(
                title="Indexing metadata revealed a sensitive public path",
                severity=Severity.MEDIUM,
                kind=FindingKind.EXPOSURE,
                url=url,
                description=(
                    "robots.txt/sitemap listed a path that responds publicly "
                    "and looks security-sensitive."
                ),
                evidence=(
                    f"Indexed path returned HTTP {response.status_code}. "
                    "Response body was not stored."
                ),
                remediation=(
                    "Remove sensitive paths from public indexes and require auth."
                ),
                confidence=0.9,
                check_id="exposure.index.sensitive-path",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="exposure.index.sensitive-path",
                    proof_type="indexed_sensitive_path_public",
                    baseline_summary="Sensitive indexed paths should not be public",
                    mutation_summary="Safe GET to robots/sitemap-discovered URL",
                    observed_result=finding.evidence,
                    confidence="strong",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    return findings


async def run_exposure_pack_v2(
    crawl: CrawlResult,
    *,
    active: bool = False,
    scan_context: Any = None,
) -> ExposurePackResult:
    result = ExposurePackResult()
    exercised: list[str] = []

    common = await probe_common_exposures(
        crawl.target,
        scan_context=scan_context,
    )
    exercised.append("common_exposures")
    result.findings.extend(common)

    maps = await probe_source_maps(crawl.source_maps)
    exercised.append("source_maps")
    result.findings.extend(maps)

    (
        surface_obs,
        surface_findings,
    ) = analyze_user_visible_surface(
        target=crawl.target,
        pages=crawl.pages,
        links=crawl.links,
        endpoints=crawl.normalized_endpoints,
    )
    crawl.user_surface_observations.extend(surface_obs)
    exercised.append("user_visible_surface")
    result.findings.extend(surface_findings)

    (
        crawl.client_artifact_observations,
        artifact_findings,
    ) = await analyze_client_artifacts(
        crawl.js_assets,
        crawl.source_maps,
    )
    exercised.append("client_artifacts")
    result.findings.extend(artifact_findings)

    if crawl.index_robots_entries or crawl.index_sitemap_entries:
        exercised.append("index_discovery")
        index_links = set(crawl.links)
    else:
        index = await discover_index_documents(crawl.target)
        crawl.index_robots_entries = index.robots_entries
        crawl.index_sitemap_entries = index.sitemap_entries
        crawl.links.update(index.links)
        crawl.endpoints.update(index.endpoints)
        exercised.append("index_discovery")
        index_links = set(index.links)

    index_findings = await _probe_index_sensitive_paths(
        crawl.target,
        index_links,
    )
    if index_findings:
        exercised.append("index_sensitive_paths")
    result.findings.extend(index_findings)

    if active:
        (
            crawl.sensitive_endpoint_observations,
            sensitive_findings,
        ) = await probe_sensitive_endpoints(crawl.target)
        exercised.append("sensitive_endpoints")
        result.findings.extend(sensitive_findings)

    normalized: list[Finding] = []
    for finding in result.findings:
        normalized.append(_ensure_kind_and_evidence(finding))
    result.findings = normalized

    high_hardening = [
        f
        for f in result.findings
        if f.kind is FindingKind.HARDENING
        and f.severity in {Severity.HIGH, Severity.CRITICAL}
    ]
    result.coverage = {
        "pack": "exposure_v2",
        "exercised": exercised,
        "findings": len(result.findings),
        "high_hardening_count": len(high_hardening),
        "kinds": {
            "exposure": sum(
                1 for f in result.findings if f.kind is FindingKind.EXPOSURE
            ),
            "hardening": sum(
                1 for f in result.findings if f.kind is FindingKind.HARDENING
            ),
            "vulnerability": sum(
                1
                for f in result.findings
                if f.kind is FindingKind.VULNERABILITY
            ),
        },
    }
    return result
