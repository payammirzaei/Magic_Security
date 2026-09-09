"""Server-Side Safe Verification Pack v2 (STEP 23).

Wraps parameter/protocol/server probes with a uniform EvidenceObject contract:
baseline → one mutation → proof. No new destructive payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from magic_security.evidence import EvidenceObject, attach_evidence, evidence_from_finding
from magic_security.models import CrawlResult, Finding, NormalizedEndpoint
from magic_security.parameter_security import verify_parameter_security
from magic_security.protocol_security import analyze_protocol_security
from magic_security.server_coverage import build_server_security_coverage
from magic_security.server_security import run_server_security_pack


@dataclass
class ServerPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)


def _ensure_baseline_mutation_proof(finding: Finding) -> Finding:
    existing = finding.structured_evidence
    if isinstance(existing, dict) and existing.get("baseline_summary"):
        return finding

    prior = evidence_from_finding(finding)
    evidence = EvidenceObject(
        check_id=finding.check_id or prior.check_id or "server.safe",
        proof_type=prior.proof_type or "safe_active_verification",
        baseline_summary=prior.baseline_summary
        or "Benign baseline request established",
        mutation_summary=prior.mutation_summary
        or "Single controlled safe mutation applied",
        observed_result=prior.observed_result or finding.evidence,
        redacted_artifacts=dict(prior.redacted_artifacts),
        confidence=(
            "verified" if finding.verified else prior.confidence or "candidate"
        ),
        sensitive_values_stored=False,
    )
    # Preserve body-free proof fields when missing.
    if "baseline_summary" not in (evidence.redacted_artifacts or {}):
        evidence.redacted_artifacts.setdefault(
            "contract",
            "baseline→mutation→result",
        )
    attach_evidence(finding, evidence)
    return finding


async def run_server_pack(
    crawl: CrawlResult,
    *,
    endpoints: list[NormalizedEndpoint] | None = None,
) -> ServerPackResult:
    result = ServerPackResult()
    exercised: list[str] = []
    findings: list[Finding] = []
    normalized = endpoints or crawl.normalized_endpoints

    (
        crawl.parameter_security_observations,
        parameter_findings,
    ) = await verify_parameter_security(normalized)
    findings.extend(parameter_findings)
    exercised.append("parameter_security")

    (
        protocol_obs,
        protocol_findings,
    ) = await analyze_protocol_security(crawl.target)
    crawl.protocol_security_observations.extend(protocol_obs)
    findings.extend(protocol_findings)
    exercised.append("protocol_security")

    page_urls = [
        page.url for page in crawl.pages if "text/html" in page.content_type
    ]
    (
        crawl.server_security_observations,
        server_findings,
    ) = await run_server_security_pack(normalized, page_urls)
    findings.extend(server_findings)
    exercised.extend(
        [
            "path_traversal",
            "ssrf_callback",
            "auth_injection_bypass",
            "host_header",
        ]
    )

    crawl.server_security_coverage = build_server_security_coverage(
        crawl.parameter_security_observations,
        crawl.server_security_observations,
    )

    result.findings = [
        _ensure_baseline_mutation_proof(finding) for finding in findings
    ]
    result.coverage = {
        "pack": "server_v2",
        "exercised": exercised,
        "findings": len(result.findings),
        "evidence_contract": "baseline_mutation_result",
    }
    return result
