"""Multi-account workflow E2E against vulnerable_app with cleanup."""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from magic_security.budgets import RequestBudget
from magic_security.config import ScanConfig
from magic_security.context import create_scan_context
from magic_security.models import AuthContext, CrawlResult
from magic_security.scope import ScopePolicy
from magic_security.transport import attach_rate_limiter, bind_scan_context, reset_scan_context
from magic_security.workflow_packs import run_workflow_packs


def _load_demo_handler():
    path = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_app.py"
    spec = importlib.util.spec_from_file_location("magic_security_vuln_workflow_e2e", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DemoHandler


@pytest.mark.asyncio
async def test_multi_account_workflow_e2e_with_cleanup():
    Handler = _load_demo_handler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    base = f"http://127.0.0.1:{port}/"

    contexts = [
        AuthContext(
            name="user_a",
            role="customer",
            disposable=True,
            cookies={"demo_session": "A"},
        ),
        AuthContext(
            name="user_b",
            role="customer",
            disposable=True,
            cookies={"demo_session": "B"},
        ),
    ]
    config = ScanConfig(target=base, active=True, auth_contexts=tuple(contexts))
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=base, allow_remote=False)
    ctx.budgets = RequestBudget(config.budgets)
    attach_rate_limiter(ctx)
    token = bind_scan_context(ctx)

    crawl = CrawlResult(target=base)
    crawl.scan_context = ctx
    try:
        result = await run_workflow_packs(crawl, contexts, browser=False)
    finally:
        reset_scan_context(token)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert "authz_write_bola" in result.coverage.get("exercised", [])
    authz = next(item for item in result.executions if item.get("workflow") == "authz_write_bola")
    assert any(step.get("phase") == "create" for step in authz["steps"])
    assert any(step.get("phase") == "cleanup" for step in authz["steps"]) or authz.get("resources", {}).get("all_cleaned")
    assert authz["resources"].get("all_cleaned") is True
    # Force-cleanup path must run even when a mutate assertion fails later.
    assert result.coverage.get("all_resources_cleaned") is True
