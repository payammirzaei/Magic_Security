"""Regression policy engine and exit codes (STEP 40)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Exit codes
EXIT_OK = 0
EXIT_POLICY_FAIL = 1
EXIT_CONFIG_ERROR = 2
EXIT_WARN_ONLY = 3  # optional non-failing warning mode


@dataclass(frozen=True, slots=True)
class RegressionPolicy:
    fail_on_new_verified_high: bool = True
    fail_on_new_verified_critical: bool = True
    warn_on_new_verified_medium: bool = True
    fail_on_reintroduced: bool = False
    fail_on_worsened: bool = False
    ignore_unchanged_debt: bool = True
    minimum_coverage_rows: int = 0
    require_browser: bool = False
    require_auth: bool = False
    max_scan_failures: int = 50


@dataclass
class PolicyResult:
    passed: bool
    exit_code: int
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "failures": self.failures,
            "warnings": self.warnings,
            "summary": self.summary,
        }


def _is_verified(item: dict[str, Any]) -> bool:
    if item.get("verified") is True:
        return True
    return float(item.get("confidence") or 0) >= 0.95


def evaluate_policy(
    diff: dict[str, Any] | None,
    *,
    snapshot: dict[str, Any] | None = None,
    policy: RegressionPolicy | None = None,
    pack_failures: int = 0,
) -> PolicyResult:
    policy = policy or RegressionPolicy()
    result = PolicyResult(passed=True, exit_code=EXIT_OK)
    snapshot = snapshot or {}
    modes = snapshot.get("modes") or {}

    if policy.require_browser and not modes.get("browser"):
        result.failures.append("required browser mode missing")
    if policy.require_auth and not modes.get("auth_contexts"):
        result.failures.append("required auth contexts missing")
    if pack_failures > policy.max_scan_failures:
        result.failures.append(
            f"scan failures {pack_failures} exceed max {policy.max_scan_failures}"
        )

    coverage = snapshot.get("coverage") or []
    if (
        policy.minimum_coverage_rows
        and isinstance(coverage, list)
        and len(coverage) < policy.minimum_coverage_rows
    ):
        result.failures.append(
            f"coverage rows {len(coverage)} below minimum "
            f"{policy.minimum_coverage_rows}"
        )

    if diff is None:
        result.summary = {"diff": None}
        if result.failures:
            result.passed = False
            result.exit_code = EXIT_POLICY_FAIL
        return result

    new_items = list(diff.get("new") or [])
    reintroduced = list(diff.get("reintroduced") or [])
    worsened = list(diff.get("worsened") or [])
    unchanged = list(diff.get("unchanged") or [])

    for item in new_items:
        if not _is_verified(item):
            continue
        severity = str(item.get("severity") or "").lower()
        title = item.get("title") or item.get("fingerprint")
        if severity == "critical" and policy.fail_on_new_verified_critical:
            result.failures.append(f"new verified critical: {title}")
        elif severity == "high" and policy.fail_on_new_verified_high:
            result.failures.append(f"new verified high: {title}")
        elif severity == "medium" and policy.warn_on_new_verified_medium:
            result.warnings.append(f"new verified medium: {title}")

    if policy.fail_on_reintroduced:
        for item in reintroduced:
            if _is_verified(item):
                result.failures.append(
                    f"reintroduced verified: {item.get('title')}"
                )

    if policy.fail_on_worsened:
        for item in worsened:
            result.failures.append(f"worsened: {item.get('title')}")

    result.summary = {
        "new": len(new_items),
        "reintroduced": len(reintroduced),
        "worsened": len(worsened),
        "unchanged": len(unchanged),
        "ignored_unchanged_debt": policy.ignore_unchanged_debt,
    }

    if result.failures:
        result.passed = False
        result.exit_code = EXIT_POLICY_FAIL
    elif result.warnings and not result.failures:
        # Warnings alone do not fail by default.
        result.exit_code = EXIT_OK
    return result
