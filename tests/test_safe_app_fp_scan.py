"""STEP 60 — safe_app scan should not emit verified vulnerabilities."""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from magic_security.config import ScanConfig
from magic_security.engine import ScannerEngine
from magic_security.models import FindingKind


def _load_safe_handler():
    path = Path(__file__).resolve().parents[1] / "examples" / "safe_app.py"
    spec = importlib.util.spec_from_file_location("magic_security_safe_app", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SafeHandler


@pytest.mark.asyncio
async def test_safe_app_scan_has_no_verified_vulnerabilities():
    Handler = _load_safe_handler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    base = f"http://127.0.0.1:{port}/"
    try:
        crawl, findings = await ScannerEngine().scan(
            ScanConfig(target=base, max_pages=12, active=True, browser=False)
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    verified_vulns = [
        f for f in findings if f.kind is FindingKind.VULNERABILITY and f.verified
    ]
    assert verified_vulns == [], [f.title for f in verified_vulns]
    assert crawl.pages or crawl.normalized_endpoints or crawl.links
