"""Typed scan configuration (STEP 4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from magic_security.models import AuthContext


@dataclass(frozen=True, slots=True)
class ScopeConfig:
    """Filled by STEP 6; defaults match localhost-only MVP."""

    loopback_only: bool = True
    allowed_hosts: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()
    same_origin: bool = True
    deny_external_redirects: bool = True


@dataclass(frozen=True, slots=True)
class BudgetConfig:
    """Filled by STEP 7; high defaults preserve current demo behavior."""

    max_total_requests: int = 10_000
    max_requests_per_endpoint: int = 200
    max_response_bytes: int = 2_000_000
    max_redirects: int = 10
    max_pages: int | None = None  # None → use ScanConfig.max_pages
    max_active_mutations: int = 5_000
    max_browser_navigations: int = 500


@dataclass(frozen=True, slots=True)
class RateConfig:
    """Filled by STEP 8; conservative defaults."""

    global_concurrency: int = 4
    per_host_concurrency: int = 2
    requests_per_second: float = 5.0
    backoff_on_status: tuple[int, ...] = (429, 503)


@dataclass(frozen=True, slots=True)
class ScanConfig:
    target: str
    max_pages: int = 100
    browser: bool = False
    active: bool = False
    auth_contexts: tuple = ()
    allow_remote: bool = False
    json_path: str | None = None
    snapshot_path: str | None = None
    baseline_path: str | None = None
    workflows_path: str | None = None
    persist_history: bool = False
    history_root: str | None = None
    fail_on_policy: bool = False
    html_path: str | None = None
    repo_path: str | None = None
    trusted_local_override: bool = False
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    budgets: BudgetConfig = field(default_factory=BudgetConfig)
    rate: RateConfig = field(default_factory=RateConfig)

    def with_auth_contexts(
        self,
        contexts: list[AuthContext] | tuple[AuthContext, ...] | None,
    ) -> ScanConfig:
        return ScanConfig(
            target=self.target,
            max_pages=self.max_pages,
            browser=self.browser,
            active=self.active,
            auth_contexts=tuple(contexts or ()),
            allow_remote=self.allow_remote,
            json_path=self.json_path,
            snapshot_path=self.snapshot_path,
            baseline_path=self.baseline_path,
            workflows_path=self.workflows_path,
            persist_history=self.persist_history,
            history_root=self.history_root,
            fail_on_policy=self.fail_on_policy,
            html_path=self.html_path,
            repo_path=self.repo_path,
            trusted_local_override=self.trusted_local_override,
            scope=self.scope,
            budgets=self.budgets,
            rate=self.rate,
        )


def scan_config_from_flags(
    *,
    target: str,
    max_pages: int = 100,
    browser: bool = False,
    active: bool = False,
    auth_contexts: list[AuthContext] | tuple[AuthContext, ...] | None = None,
    allow_remote: bool = False,
    json_path: str | None = None,
    snapshot_path: str | None = None,
    baseline_path: str | None = None,
    workflows_path: str | None = None,
    persist_history: bool = False,
    history_root: str | None = None,
    fail_on_policy: bool = False,
    html_path: str | None = None,
    repo_path: str | None = None,
    trusted_local_override: bool = False,
) -> ScanConfig:
    return ScanConfig(
        target=target,
        max_pages=max_pages,
        browser=browser,
        active=active,
        auth_contexts=tuple(auth_contexts or ()),
        allow_remote=allow_remote,
        json_path=json_path,
        snapshot_path=snapshot_path,
        baseline_path=baseline_path,
        workflows_path=workflows_path,
        persist_history=persist_history,
        history_root=history_root,
        fail_on_policy=fail_on_policy,
        html_path=html_path,
        repo_path=repo_path,
        trusted_local_override=trusted_local_override,
        budgets=BudgetConfig(max_pages=max_pages),
    )
