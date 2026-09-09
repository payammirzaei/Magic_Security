"""STEP 61 — false-negative pack smoke against vulnerable_app fixtures."""

from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from magic_security.injection import verify_reflected_html_injection
from magic_security.models import NormalizedEndpoint
from magic_security.server_security import run_server_security_pack


def _load_demo_handler():
    path = Path(__file__).resolve().parents[1] / "examples" / "vulnerable_app.py"
    spec = importlib.util.spec_from_file_location("magic_security_vuln_fn", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DemoHandler


@pytest.mark.asyncio
async def test_fn_injection_and_server_packs_find_verified_signals():
    Handler = _load_demo_handler()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    base = f"http://127.0.0.1:{port}"
    try:
        endpoints = [
            NormalizedEndpoint(
                url=f"{base}/reflect",
                method="GET",
                parameters=("q",),
            ),
            NormalizedEndpoint(
                url=f"{base}/download",
                method="GET",
                parameters=("file",),
            ),
            NormalizedEndpoint(
                url=f"{base}/fetch",
                method="GET",
                parameters=("url",),
            ),
        ]
        inj_obs, inj_findings = await verify_reflected_html_injection(endpoints)
        srv_obs, srv_findings = await run_server_security_pack(
            endpoints,
            [f"{base}/"],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    verified = [
        *([o for o in inj_obs if getattr(o, "verified", False)]),
        *([o for o in srv_obs if getattr(o, "verified", False)]),
        *([f for f in inj_findings + srv_findings if f.verified]),
    ]
    assert verified, "FN corpus expected at least one verified signal on demo fixtures"
