"""Authorization Matrix Engine v2 (STEP 29)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import (
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)


ExpectedOutcome = Literal["allow", "deny", "unknown"]
ObservedOutcome = Literal["allow", "deny", "error", "unknown"]


@dataclass
class AuthzMatrixRow:
    subject: str
    role: str | None
    action: str
    resource: str
    ownership: str
    expected: ExpectedOutcome
    observed: ObservedOutcome
    verified: bool = False
    evidence_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuthzMatrixResult:
    rows: list[AuthzMatrixRow] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)


def _observed_from_status(status: int) -> ObservedOutcome:
    if status in {401, 403}:
        return "deny"
    if 200 <= status < 300:
        return "allow"
    if status >= 500:
        return "error"
    return "unknown"


def build_authz_matrix(
    crawl: CrawlResult,
    *,
    roles: dict[str, str | None] | None = None,
) -> AuthzMatrixResult:
    result = AuthzMatrixResult()
    role_map = roles or {}
    rows: list[AuthzMatrixRow] = []

    for comparison in crawl.auth_comparisons:
        for context_name, status in comparison.context_statuses:
            expected: ExpectedOutcome = "unknown"
            if comparison.boundary == "protected":
                expected = "allow"
            elif comparison.boundary == "public":
                expected = "allow"
            observed = _observed_from_status(status)
            rows.append(
                AuthzMatrixRow(
                    subject=context_name,
                    role=role_map.get(context_name),
                    action=comparison.method.upper(),
                    resource=comparison.url,
                    ownership="self_or_shared",
                    expected=expected,
                    observed=observed,
                    verified=False,
                    evidence_summary=(
                        f"boundary={comparison.boundary}; status={status}"
                    ),
                )
            )

    for item in crawl.ownership_observations:
        rows.append(
            AuthzMatrixRow(
                subject=item.context,
                role=role_map.get(item.context),
                action="OWN",
                resource=f"param:{item.parameter}",
                ownership="owner",
                expected="allow",
                observed="allow" if item.discovered_values else "unknown",
                verified=False,
                evidence_summary=(
                    f"discovered_values={item.discovered_values}"
                ),
            )
        )

    for item in crawl.pairwise_idor_observations:
        expected: ExpectedOutcome = "deny"
        observed: ObservedOutcome = (
            "allow" if item.cross_account_verified else "deny"
        )
        if item.requester_status >= 500:
            observed = "error"
        elif not item.cross_account_verified:
            observed = _observed_from_status(item.requester_status)
            if observed == "allow" and not item.cross_account_verified:
                # Status allow without semantic match stays unknown/deny.
                observed = "deny"

        verified = expected == "deny" and item.cross_account_verified
        row = AuthzMatrixRow(
            subject=item.requester_context,
            role=role_map.get(item.requester_context),
            action="READ",
            resource=item.endpoint,
            ownership=f"owned_by:{item.owner_context}",
            expected=expected,
            observed="allow" if item.cross_account_verified else observed,
            verified=verified,
            evidence_summary=(
                f"{item.requester_context} accessed {item.owner_context}'s "
                f"resource via {item.parameter_location}:{item.parameter}; "
                f"owner_status={item.owner_status}; "
                f"requester_status={item.requester_status}; "
                f"cross_account_verified={item.cross_account_verified}"
            ),
        )
        rows.append(row)

        if verified:
            finding = Finding(
                title="Authorization matrix: expected deny, observed allow",
                severity=Severity.HIGH,
                kind=FindingKind.VULNERABILITY,
                url=item.endpoint,
                description=(
                    f"Subject {item.requester_context!r} accessed subject "
                    f"{item.owner_context!r}'s resource when deny was expected."
                ),
                evidence=row.evidence_summary
                + ". Raw object bodies and identifiers were not stored.",
                remediation=(
                    "Enforce object-level authorization for cross-account reads."
                ),
                confidence=1.0,
                check_id="authorization.matrix.deny-allow",
                owasp="A01:2025 Broken Access Control",
                cwe="CWE-639",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="authorization.matrix.deny-allow",
                    proof_type="authz_matrix_expected_deny_observed_allow",
                    baseline_summary=(
                        f"Owner {item.owner_context} read own resource"
                    ),
                    mutation_summary=(
                        f"Requester {item.requester_context} read owner resource"
                    ),
                    observed_result=row.evidence_summary,
                    confidence="verified",
                    sensitive_values_stored=False,
                    redacted_artifacts={
                        "owner_status": item.owner_status,
                        "requester_status": item.requester_status,
                    },
                ),
            )
            result.findings.append(finding)

    result.rows = rows
    crawl.authz_matrix = [row.to_dict() for row in rows]
    result.coverage = {
        "pack": "authz_matrix_v2",
        "rows": len(rows),
        "verified_violations": sum(1 for row in rows if row.verified),
        "model": [
            "Subject",
            "Role",
            "Action",
            "Resource",
            "Ownership",
            "Expected",
            "Observed",
        ],
    }
    return result
