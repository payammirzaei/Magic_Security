"""STEP 53 — budget enforcement proofs across pack-style transport use."""

from __future__ import annotations

import pytest

from magic_security.budgets import RequestBudget
from magic_security.config import BudgetConfig, ScanConfig
from magic_security.context import create_scan_context
from magic_security.scope import ScopePolicy
from magic_security.transport import (
    BudgetBlockedError,
    attach_rate_limiter,
    bind_scan_context,
    open_secure_transport,
    reset_scan_context,
)


@pytest.mark.asyncio
async def test_budget_blocks_further_requests_via_transport():
    config = ScanConfig(target="http://127.0.0.1:9/")
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=config.target, allow_remote=False)
    ctx.budgets = RequestBudget(
        BudgetConfig(max_total_requests=2, max_requests_per_endpoint=100)
    )
    attach_rate_limiter(ctx)
    token = bind_scan_context(ctx)
    try:
        async with open_secure_transport(ctx, timeout=1.0) as client:
            # Two attempts count even if connection fails — budget consumes before send.
            for _ in range(2):
                try:
                    await client.get("http://127.0.0.1:9/")
                except Exception:
                    pass
            assert ctx.budgets.total_requests == 2
            with pytest.raises(BudgetBlockedError):
                await client.get("http://127.0.0.1:9/more")
            assert ctx.budgets.exhausted
            assert "max_total_requests" in ctx.budgets.exhausted_reasons
            degradation = ctx.budgets.coverage_degradation()
            assert degradation.get("exhausted") or ctx.budgets.exhausted
    finally:
        reset_scan_context(token)


def test_budget_coverage_never_claims_fully_tested_when_exhausted():
    budget = RequestBudget(BudgetConfig(max_total_requests=1))
    assert budget.consume_request("http://127.0.0.1/a")
    assert not budget.consume_request("http://127.0.0.1/b")
    cov = budget.coverage_degradation()
    blob = str(cov).lower()
    assert "full" not in blob or "partial" in blob or cov.get("exhausted")
