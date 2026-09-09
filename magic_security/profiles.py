"""Scan profiles including production-safe remote (STEP 44)."""

from __future__ import annotations

from dataclasses import replace

from magic_security.config import (
    BudgetConfig,
    RateConfig,
    ScanConfig,
    ScopeConfig,
)


def production_safe_remote_profile(
    target: str,
    *,
    allowed_hosts: tuple[str, ...] = (),
    denied_paths: tuple[str, ...] = (
        "/admin",
        "/logout",
        "/payment",
        "/checkout",
        "/delete",
    ),
    browser: bool = True,
) -> ScanConfig:
    """Conservative profile for owned production/staging hosts.

    - passive + bounded safe GET / optional browser discovery
    - no generic workflows / mutations unless caller overrides later
    - strict budgets, rate, timeouts via budgets/rate
    """
    return ScanConfig(
        target=target,
        max_pages=40,
        browser=browser,
        active=True,  # safe-active only; workflows remain gated
        allow_remote=True,
        workflows_path=None,
        fail_on_policy=True,
        scope=ScopeConfig(
            loopback_only=False,
            allowed_hosts=allowed_hosts,
            denied_paths=denied_paths,
            same_origin=True,
            deny_external_redirects=True,
        ),
        budgets=BudgetConfig(
            max_total_requests=400,
            max_requests_per_endpoint=20,
            max_response_bytes=500_000,
            max_redirects=3,
            max_pages=40,
            max_active_mutations=0,
            max_browser_navigations=30,
        ),
        rate=RateConfig(
            global_concurrency=2,
            per_host_concurrency=1,
            requests_per_second=1.0,
            backoff_on_status=(429, 503),
        ),
    )


def apply_profile_overrides(
    config: ScanConfig,
    *,
    enable_workflows: bool = False,
) -> ScanConfig:
    if enable_workflows:
        return replace(
            config,
            budgets=replace(
                config.budgets,
                max_active_mutations=max(config.budgets.max_active_mutations, 20),
            ),
        )
    return config
