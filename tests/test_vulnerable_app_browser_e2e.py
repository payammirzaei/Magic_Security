"""Real vulnerable_app Playwright E2E (browser XSS verification)."""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from magic_security.budgets import RequestBudget
from magic_security.config import ScanConfig
from magic_security.context import create_scan_context
from magic_security.injection import verify_reflected_xss_browser
from magic_security.models import NormalizedEndpoint
from magic_security.scope import ScopePolicy
from magic_security.transport import attach_rate_limiter, bind_scan_context, reset_scan_context


def _load_demo_handler():
    path = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_app.py"
    spec = importlib.util.spec_from_file_location("magic_security_vuln_browser_e2e", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DemoHandler


@pytest.mark.asyncio
async def test_vulnerable_app_playwright_reflected_xss_e2e():
    pytest.importorskip("playwright.async_api")

    Handler = _load_demo_handler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    base = f"http://127.0.0.1:{port}"

    config = ScanConfig(target=f"{base}/", browser=True, active=True)
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=config.target, allow_remote=False)
    ctx.budgets = RequestBudget(config.budgets)
    attach_rate_limiter(ctx)
    token = bind_scan_context(ctx)

    endpoints = [
        NormalizedEndpoint(
            url=f"{base}/reflect",
            method="GET",
            parameters=("q",),
            sources=("e2e",),
        )
    ]
    try:
        observations, findings = await verify_reflected_xss_browser(endpoints, max_tests=3)
    finally:
        reset_scan_context(token)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    verified = [item for item in findings if item.verified] or [
        item for item in observations if getattr(item, "verified", False)
    ]
    assert verified, "expected Playwright-verified reflected XSS on vulnerable_app /reflect"
