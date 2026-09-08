from __future__ import annotations

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from magic_security.models import NormalizedEndpoint
from magic_security.server_security import run_server_security_pack


def _load_demo_handler():
    path = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "vulnerable_app.py"
    )
    spec = importlib.util.spec_from_file_location(
        "magic_security_vulnerable_demo",
        path,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.DemoHandler


@pytest.mark.asyncio
async def test_vulnerable_demo_server_pack_end_to_end():
    DemoHandler = _load_demo_handler()

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        DemoHandler,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    port = int(server.server_address[1])
    base = f"http://127.0.0.1:{port}"

    endpoints = [
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
        NormalizedEndpoint(
            url=f"{base}/api/login",
            method="POST",
            parameters=("email", "username", "password"),
        ),
    ]

    try:
        observations, findings = await run_server_security_pack(
            endpoints,
            [f"{base}/absolute"],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    verified = {
        item.category
        for item in observations
        if item.verified
    }

    assert "path_traversal" in verified
    assert "ssrf" in verified
    assert "auth_sqli" in verified
    assert "auth_nosqli" in verified
    assert "host_header" in verified

    titles = {item.title for item in findings}
    assert "Path traversal / local file read verified" in titles
    assert "Server-side request forgery verified" in titles
    assert "SQL-style authentication bypass verified" in titles
    assert "NoSQL operator authentication bypass verified" in titles
    assert "Untrusted Host header influences response content" in titles
