"""Check registry (STEP 13)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from magic_security.check_spec import Check, CheckSpec, LegacyPageCheckAdapter, RiskClass
from magic_security.checks.cookies import CookieSecurityCheck
from magic_security.checks.exposures import ExposureHeuristicCheck
from magic_security.checks.headers import SecurityHeaderCheck
from magic_security.models import FindingKind


class CheckStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    SKIPPED_PROFILE = "skipped_by_profile"
    SKIPPED_AUTH = "skipped_due_to_missing_auth"
    SKIPPED_BROWSER = "skipped_due_to_missing_browser"
    BLOCKED_SAFETY = "blocked_by_safety"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class RegisteredCheck:
    spec: CheckSpec
    check: Check
    status: CheckStatus = CheckStatus.ENABLED
    detail: str = ""


@dataclass
class CheckRegistry:
    _checks: dict[str, RegisteredCheck] = field(default_factory=dict)
    _run_log: list[dict[str, str]] = field(default_factory=list)

    def register(self, check: Check) -> None:
        check_id = check.spec.check_id
        if check_id in self._checks:
            raise ValueError(f"Duplicate check_id: {check_id}")
        self._checks[check_id] = RegisteredCheck(spec=check.spec, check=check)

    def get(self, check_id: str) -> RegisteredCheck | None:
        return self._checks.get(check_id)

    def list_checks(self) -> list[RegisteredCheck]:
        return sorted(self._checks.values(), key=lambda item: item.spec.check_id)

    def by_pack(self) -> dict[str, list[RegisteredCheck]]:
        packs: dict[str, list[RegisteredCheck]] = {}
        for item in self.list_checks():
            packs.setdefault(item.spec.pack, []).append(item)
        return packs

    def resolve_for_profile(
        self,
        *,
        active: bool,
        browser: bool,
        auth_enabled: bool,
        workflow_enabled: bool = False,
    ) -> list[RegisteredCheck]:
        selected: list[RegisteredCheck] = []
        for item in self.list_checks():
            modes = set(item.spec.required_modes)
            if "active" in modes and not active:
                item.status = CheckStatus.SKIPPED_PROFILE
                item.detail = "active mode disabled"
                continue
            if "browser" in modes and not browser:
                item.status = CheckStatus.SKIPPED_BROWSER
                item.detail = "browser mode disabled"
                continue
            if "auth" in modes and not auth_enabled:
                item.status = CheckStatus.SKIPPED_AUTH
                item.detail = "auth contexts missing"
                continue
            if "workflow" in item.spec.prerequisites and not workflow_enabled:
                item.status = CheckStatus.SKIPPED_PROFILE
                item.detail = "workflow prerequisite missing"
                continue
            item.status = CheckStatus.ENABLED
            item.detail = ""
            selected.append(item)
        return selected

    def record_execution(self, check_id: str, status: CheckStatus, detail: str = "") -> None:
        item = self._checks.get(check_id)
        if item is not None:
            item.status = status
            item.detail = detail
        self._run_log.append(
            {
                "check_id": check_id,
                "status": status.value,
                "detail": detail,
            }
        )

    def coverage_rows(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for item in self.list_checks():
            rows.append(
                {
                    "check_id": item.spec.check_id,
                    "pack": item.spec.pack,
                    "status": item.status.value,
                    "detail": item.detail,
                    "category": item.spec.category,
                }
            )
        return rows


def build_default_registry() -> CheckRegistry:
    registry = CheckRegistry()
    adapters = [
        LegacyPageCheckAdapter(
            SecurityHeaderCheck(),
            CheckSpec(
                check_id="hardening.header.missing",
                title="Missing security headers",
                category="security_headers",
                required_modes=("http",),
                risk_class=RiskClass.PASSIVE,
                proof_condition="response_missing_expected_header",
                finding_kind=FindingKind.HARDENING,
                pack="passive",
            ),
        ),
        LegacyPageCheckAdapter(
            CookieSecurityCheck(),
            CheckSpec(
                check_id="session.cookie.missing-attributes",
                title="Cookie security attributes",
                category="session",
                required_modes=("http",),
                risk_class=RiskClass.PASSIVE,
                proof_condition="cookie_attribute_inspection",
                finding_kind=FindingKind.HARDENING,
                pack="passive",
            ),
        ),
        LegacyPageCheckAdapter(
            ExposureHeuristicCheck(),
            CheckSpec(
                check_id="exposure.heuristic.page",
                title="Page exposure heuristics",
                category="information_disclosure",
                required_modes=("http",),
                risk_class=RiskClass.PASSIVE,
                proof_condition="page_content_signature",
                finding_kind=FindingKind.EXPOSURE,
                pack="passive",
            ),
        ),
    ]
    for adapter in adapters:
        registry.register(adapter)

    # Metadata-only registrations for major active packs (wrappers come later).
    for spec in _PACK_SPECS:
        if spec.check_id in registry._checks:
            continue
        registry.register(_MetadataOnlyCheck(spec))
    return registry


@dataclass
class _MetadataOnlyCheck:
    spec: CheckSpec

    async def execute(self, context: Any) -> list:
        return []


_PACK_SPECS = (
    CheckSpec(
        check_id="cors.arbitrary-origin",
        title="Arbitrary CORS origin reflection",
        category="cors",
        required_modes=("active",),
        risk_class=RiskClass.SAFE_ACTIVE,
        proof_condition="reflected_acao",
        finding_kind=FindingKind.EXPOSURE,
        pack="active",
    ),
    CheckSpec(
        check_id="injection.html.reflected",
        title="Reflected HTML injection",
        category="injection",
        required_modes=("active", "browser"),
        risk_class=RiskClass.SAFE_ACTIVE,
        proof_condition="raw_html_reflection",
        finding_kind=FindingKind.VULNERABILITY,
        pack="browser",
    ),
    CheckSpec(
        check_id="authorization.bola.read",
        title="Cross-account object read",
        category="authorization",
        required_modes=("auth",),
        prerequisites=("auth_contexts",),
        risk_class=RiskClass.AUTH,
        proof_condition="pairwise_cross_account_read",
        finding_kind=FindingKind.VULNERABILITY,
        pack="authorization",
    ),
    CheckSpec(
        check_id="xss.dom.execution",
        title="DOM XSS execution",
        category="xss",
        required_modes=("browser", "active"),
        risk_class=RiskClass.BROWSER,
        proof_condition="runtime_canary_execution",
        finding_kind=FindingKind.VULNERABILITY,
        pack="browser",
    ),
    CheckSpec(
        check_id="exposure.external.pack",
        title="External exposure pack v2",
        category="information_disclosure",
        required_modes=("http",),
        risk_class=RiskClass.PASSIVE,
        proof_condition="public_resource_observation",
        finding_kind=FindingKind.EXPOSURE,
        pack="exposure",
    ),
    CheckSpec(
        check_id="api.undocumented.public",
        title="Undocumented public API routes",
        category="api",
        required_modes=("active",),
        risk_class=RiskClass.SAFE_ACTIVE,
        proof_condition="openapi_vs_crawl_diff",
        finding_kind=FindingKind.EXPOSURE,
        pack="api",
    ),
    CheckSpec(
        check_id="api.mass-assignment.skipped",
        title="Mass assignment (requires workflow)",
        category="api",
        required_modes=("active",),
        prerequisites=("workflow",),
        risk_class=RiskClass.SAFE_ACTIVE,
        proof_condition="requires_config",
        finding_kind=FindingKind.HARDENING,
        pack="api",
    ),
    CheckSpec(
        check_id="graphql.introspection.anonymous",
        title="Anonymous GraphQL introspection",
        category="graphql",
        required_modes=("active",),
        risk_class=RiskClass.SAFE_ACTIVE,
        proof_condition="introspection_schema",
        finding_kind=FindingKind.EXPOSURE,
        pack="graphql",
    ),
    CheckSpec(
        check_id="websocket.cswsh.accepted",
        title="Cross-origin WebSocket accepted",
        category="websocket",
        required_modes=("browser",),
        risk_class=RiskClass.BROWSER,
        proof_condition="cross_origin_ws_accepted",
        finding_kind=FindingKind.VULNERABILITY,
        pack="websocket",
    ),
    CheckSpec(
        check_id="auth.enumeration.signal",
        title="Account enumeration signal",
        category="authentication",
        required_modes=("auth",),
        risk_class=RiskClass.AUTH,
        proof_condition="login_differential_observation",
        finding_kind=FindingKind.EXPOSURE,
        pack="authentication",
    ),
    CheckSpec(
        check_id="authorization.matrix.deny-allow",
        title="Authorization matrix deny/allow violation",
        category="authorization",
        required_modes=("auth",),
        prerequisites=("auth_contexts",),
        risk_class=RiskClass.AUTH,
        proof_condition="authz_matrix_expected_deny_observed_allow",
        finding_kind=FindingKind.VULNERABILITY,
        pack="authorization",
    ),
    CheckSpec(
        check_id="workflow.authz.write",
        title="Disposable write BOLA workflow",
        category="authorization",
        required_modes=("auth",),
        prerequisites=("workflow", "auth_contexts"),
        risk_class=RiskClass.WORKFLOW,
        proof_condition="workflow_cross_account_mutate",
        finding_kind=FindingKind.VULNERABILITY,
        pack="workflow",
        may_mutate_state=True,
        requires_workflow_authorization=True,
    ),
    CheckSpec(
        check_id="workflow.stored_xss",
        title="Stored XSS canary workflow",
        category="xss",
        required_modes=("auth", "browser"),
        prerequisites=("workflow",),
        risk_class=RiskClass.WORKFLOW,
        proof_condition="stored_canary_reflection",
        finding_kind=FindingKind.VULNERABILITY,
        pack="workflow",
        may_mutate_state=True,
        requires_workflow_authorization=True,
    ),
)
