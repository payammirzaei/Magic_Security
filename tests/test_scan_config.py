from __future__ import annotations

import pytest

from magic_security.config import (
    BudgetConfig,
    RateConfig,
    ScanConfig,
    ScopeConfig,
    scan_config_from_flags,
)
from magic_security.engine import ScannerEngine
from magic_security.models import AuthContext


def test_default_scan_config_matches_current_behavior():
    config = scan_config_from_flags(target="http://127.0.0.1:8000")
    assert config.max_pages == 100
    assert config.browser is False
    assert config.active is False
    assert config.auth_contexts == ()
    assert config.allow_remote is False
    assert isinstance(config.scope, ScopeConfig)
    assert config.scope.loopback_only is True
    assert isinstance(config.budgets, BudgetConfig)
    assert isinstance(config.rate, RateConfig)


def test_scan_config_preserves_cli_flag_mapping():
    contexts = (
        AuthContext(name="a", cookies={"s": "1"}),
        AuthContext(name="b", cookies={"s": "2"}),
    )
    config = scan_config_from_flags(
        target="http://localhost:9000",
        max_pages=25,
        browser=True,
        active=True,
        auth_contexts=contexts,
        json_path="out.json",
        snapshot_path="snap.json",
        baseline_path="base.json",
    )
    assert config.target == "http://localhost:9000"
    assert config.max_pages == 25
    assert config.browser is True
    assert config.active is True
    assert len(config.auth_contexts) == 2
    assert config.json_path == "out.json"
    assert config.snapshot_path == "snap.json"
    assert config.baseline_path == "base.json"


@pytest.mark.asyncio
async def test_engine_accepts_scan_config_and_kwargs_shim():
    engine = ScannerEngine(max_pages=5)
    config = ScanConfig(target="http://example.com", allow_remote=False)
    with pytest.raises(ValueError, match="localhost/loopback"):
        await engine.scan(config=config)

    with pytest.raises(ValueError, match="localhost/loopback"):
        await engine.scan("http://example.com")
