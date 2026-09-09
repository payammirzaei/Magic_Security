"""Standardized evidence objects (STEP 11)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from magic_security.models import ConfidenceLevel, Finding
from magic_security.redaction import Redactor


@dataclass(slots=True)
class EvidenceObject:
    check_id: str
    proof_type: str
    baseline_summary: str = ""
    mutation_summary: str = ""
    observed_result: str = ""
    redacted_artifacts: dict[str, Any] = field(default_factory=dict)
    confidence: str = ConfidenceLevel.CANDIDATE.value
    sensitive_values_stored: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_legacy_string(self) -> str:
        parts = [
            part
            for part in (
                self.baseline_summary,
                self.mutation_summary,
                self.observed_result,
            )
            if part
        ]
        if not parts:
            return f"check={self.check_id}; proof={self.proof_type}"
        return " ".join(parts)


def evidence_from_legacy_string(
    check_id: str,
    evidence: str,
    *,
    proof_type: str = "legacy_text",
    confidence: float = 1.0,
) -> EvidenceObject:
    level = ConfidenceLevel.VERIFIED.value
    if confidence < 0.95:
        level = ConfidenceLevel.STRONG.value
    if confidence < 0.80:
        level = ConfidenceLevel.LIKELY.value
    if confidence < 0.50:
        level = ConfidenceLevel.CANDIDATE.value

    scrubbed = Redactor().redact_text(evidence)
    return EvidenceObject(
        check_id=check_id,
        proof_type=proof_type,
        observed_result=scrubbed,
        confidence=level,
        sensitive_values_stored=False,
    )


def attach_evidence(finding: Finding, evidence: EvidenceObject) -> Finding:
    finding.check_id = finding.check_id or evidence.check_id
    finding.evidence = evidence.to_legacy_string()
    finding.structured_evidence = evidence.to_dict()
    return finding


def evidence_from_finding(finding: Finding) -> EvidenceObject:
    existing = finding.structured_evidence
    if isinstance(existing, dict) and existing.get("check_id"):
        return EvidenceObject(**existing)
    return evidence_from_legacy_string(
        finding.check_id or "legacy.unknown",
        finding.evidence,
        confidence=finding.confidence,
    )
