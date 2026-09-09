"""Standardized check interface (STEP 12)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from magic_security.models import Finding, FindingKind, PageSnapshot


class RiskClass(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    AUTH = "auth"
    BROWSER = "browser"
    WORKFLOW = "workflow"


@dataclass(frozen=True, slots=True)
class CheckSpec:
    check_id: str
    title: str
    category: str
    required_modes: tuple[str, ...] = ("http",)
    prerequisites: tuple[str, ...] = ()
    risk_class: RiskClass = RiskClass.PASSIVE
    may_mutate_state: bool = False
    requires_workflow_authorization: bool = False
    proof_condition: str = ""
    evidence_policy: str = "minimal_redacted"
    default_coverage_outcome: str = "Partially Tested"
    finding_kind: FindingKind = FindingKind.HARDENING
    pack: str = "core"


class Check(Protocol):
    spec: CheckSpec

    async def execute(self, context: Any) -> list[Finding]:
        ...


class PageCheck(Protocol):
    """Legacy synchronous page-oriented check."""

    name: str

    def run(self, page: PageSnapshot) -> list[Finding]:
        ...


@dataclass
class LegacyPageCheckAdapter:
    """Wraps existing page checks into the standardized Check interface."""

    inner: PageCheck
    spec: CheckSpec

    async def execute(self, context: Any) -> list[Finding]:
        crawl = getattr(context, "crawl", None)
        if crawl is None:
            return []
        findings: list[Finding] = []
        for page in crawl.pages:
            findings.extend(self.inner.run(page))
        for finding in findings:
            if not finding.check_id:
                finding.check_id = self.spec.check_id
        return findings
