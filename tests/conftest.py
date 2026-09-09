"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from magic_security.budgets import RequestBudget
from magic_security.config import ScanConfig
from magic_security.context import create_scan_context
from magic_security.scope import ScopePolicy
from magic_security.transport import (
    attach_rate_limiter,
    bind_scan_context,
    reset_scan_context,
)


@pytest.fixture(autouse=True)
def _bind_loopback_scan_context():
    """Provide a loopback-only ScanContext for pack unit tests (STEP 51).

    Engine scans call bind_scan_context() themselves and override this binding
    for the duration of the scan. Unbound production call sites still fail closed.
    """
    config = ScanConfig(target="http://127.0.0.1:8000/")
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=config.target, allow_remote=False)
    ctx.budgets = RequestBudget(config.budgets)
    attach_rate_limiter(ctx)
    token = bind_scan_context(ctx)
    try:
        yield ctx
    finally:
        reset_scan_context(token)
