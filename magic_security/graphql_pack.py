"""GraphQL Security Pack v2 (STEP 25) — beyond introspection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.graphql_security import (
    analyze_graphql,
    probe_graphql_depth,
    probe_graphql_sensitive_fields,
    probe_graphql_subscriptions,
)
from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    NormalizedEndpoint,
)


@dataclass
class GraphqlPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)


async def run_graphql_pack(
    crawl: CrawlResult,
    *,
    endpoints: list[NormalizedEndpoint] | None = None,
    auth_contexts: list[AuthContext] | None = None,
) -> GraphqlPackResult:
    result = GraphqlPackResult()
    exercised: list[str] = []
    skipped: list[str] = []
    findings: list[Finding] = []
    normalized = endpoints or crawl.normalized_endpoints

    (
        crawl.graphql_observations,
        introspection_findings,
    ) = await analyze_graphql(normalized)
    findings.extend(introspection_findings)
    exercised.append("introspection")
    exercised.append("debug_errors")

    introspected = [
        item for item in crawl.graphql_observations if item.anonymous_introspection
    ]
    if introspected:
        (
            field_findings,
            field_coverage,
        ) = await probe_graphql_sensitive_fields(
            [item.url for item in introspected],
            auth_contexts=auth_contexts,
        )
        findings.extend(field_findings)
        exercised.extend(field_coverage.get("exercised", []))
        skipped.extend(field_coverage.get("skipped", []))
    else:
        skipped.append("sensitive_field_probe")
        skipped.append("auth_field_comparison")

    (
        depth_findings,
        depth_meta,
    ) = await probe_graphql_depth(
        [item.url for item in crawl.graphql_observations]
    )
    findings.extend(depth_findings)
    exercised.extend(depth_meta.get("exercised", ["depth_complexity"]))

    (
        sub_findings,
        sub_meta,
    ) = await probe_graphql_subscriptions(
        crawl,
        [item.url for item in crawl.graphql_observations],
    )
    findings.extend(sub_findings)
    exercised.extend(sub_meta.get("exercised", ["subscription_discovery"]))

    for finding in findings:
        if finding.structured_evidence is None:
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id=finding.check_id or "graphql.pack",
                    proof_type="graphql_bounded_probe",
                    baseline_summary="GraphQL baseline introspection/query",
                    mutation_summary="Bounded read-only GraphQL probe",
                    observed_result=finding.evidence,
                    confidence=(
                        "verified" if finding.verified else "likely"
                    ),
                    sensitive_values_stored=False,
                ),
            )

    result.findings = findings
    result.coverage = {
        "pack": "graphql_v2",
        "exercised": sorted(set(exercised)),
        "skipped": sorted(set(skipped)),
        "endpoints_tested": len(crawl.graphql_observations),
        "depth_cap": 5,
        "alias_cap": 5,
    }
    return result
