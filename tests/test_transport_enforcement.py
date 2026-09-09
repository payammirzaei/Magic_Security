"""STEP 51 — network safety / transport enforcement proofs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from magic_security.budgets import RequestBudget
from magic_security.config import ScanConfig
from magic_security.context import create_scan_context
from magic_security.scope import ScopePolicy
from magic_security.transport import (
    ScopeBlockedError,
    assert_url_in_scope,
    attach_rate_limiter,
    bind_scan_context,
    open_secure_transport,
    reset_scan_context,
)


ROOT = Path(__file__).resolve().parents[1] / "magic_security"


def _bound_local_context(target: str = "http://127.0.0.1:8000/"):
    config = ScanConfig(target=target)
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=target, allow_remote=False)
    ctx.budgets = RequestBudget(config.budgets)
    attach_rate_limiter(ctx)
    return ctx


def test_no_direct_httpx_async_client_outside_transport():
    offenders: list[str] = []
    allowed = {"transport.py"}
    pattern = re.compile(r"httpx\.AsyncClient\s*\(")

    for path in ROOT.rglob("*.py"):
        if path.name in allowed:
            continue
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path.relative_to(ROOT.parent)))

    assert offenders == [], f"Direct httpx.AsyncClient usage found: {offenders}"


def test_no_banned_network_clients_in_scanner_package():
    banned = [
        re.compile(r"\burllib\.request\b"),
        re.compile(r"\bimport requests\b"),
        re.compile(r"\bfrom requests\b"),
        re.compile(r"\bimport aiohttp\b"),
        re.compile(r"\bfrom aiohttp\b"),
    ]
    offenders: list[str] = []
    for path in ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in banned:
            if pattern.search(text):
                offenders.append(f"{path.name}:{pattern.pattern}")
    assert offenders == [], f"Banned network clients: {offenders}"


def test_scanner_modules_must_not_construct_bare_secure_transport():
    """Production modules must use open_secure_transport, not SecureTransport(."""
    offenders: list[str] = []
    allowed = {"transport.py"}
    ctor = re.compile(r"(?<!open_)SecureTransport\s*\(")

    for path in ROOT.rglob("*.py"):
        if path.name in allowed:
            continue
        text = path.read_text(encoding="utf-8")
        if ctor.search(text):
            offenders.append(str(path.relative_to(ROOT.parent)))

    assert offenders == [], (
        "Bare SecureTransport( found; use open_secure_transport(): "
        f"{offenders}"
    )


@pytest.mark.asyncio
async def test_open_secure_transport_blocks_out_of_scope_without_network():
    ctx = _bound_local_context("http://127.0.0.1:8000/")
    token = bind_scan_context(ctx)
    try:
        async with open_secure_transport(
            ctx,
            follow_redirects=False,
            timeout=2.0,
        ) as client:
            with pytest.raises(ScopeBlockedError):
                await client.get("https://example.com/")
    finally:
        reset_scan_context(token)


def test_open_secure_transport_requires_bound_context():
    from magic_security.transport import _SCAN_CONTEXT

    token = _SCAN_CONTEXT.set(None)
    try:
        with pytest.raises(RuntimeError, match="No ScanContext"):
            open_secure_transport(follow_redirects=False)
    finally:
        _SCAN_CONTEXT.reset(token)


@pytest.mark.asyncio
async def test_js_asset_fetch_pattern_respects_scan_context_scope():
    """Regression for engine JS fetch bypassing ScanContext (STEP 51)."""
    ctx = _bound_local_context("http://127.0.0.1:9/")
    token = bind_scan_context(ctx)
    try:
        async with open_secure_transport(
            ctx,
            follow_redirects=True,
            timeout=5.0,
        ) as client:
            with pytest.raises(ScopeBlockedError):
                await client.get("https://evil.example/app.js")
        with pytest.raises(ScopeBlockedError):
            assert_url_in_scope("https://evil.example/app.js", ctx)
    finally:
        reset_scan_context(token)


def test_assert_url_in_scope_blocks_external():
    ctx = _bound_local_context()
    with pytest.raises(ScopeBlockedError):
        assert_url_in_scope("https://evil.example/", ctx)
    assert_url_in_scope("http://127.0.0.1:8000/ok", ctx)
