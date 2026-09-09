"""Transport safety: redirects, streaming caps, DNS rebinding TOCTOU."""

from __future__ import annotations

import socket
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from magic_security.budgets import RequestBudget
from magic_security.config import BudgetConfig, ScanConfig
from magic_security.context import create_scan_context
from magic_security.scope import ScopePolicy
from magic_security.transport import (
    ResponseTooLargeError,
    ScopeBlockedError,
    attach_rate_limiter,
    bind_scan_context,
    open_secure_transport,
    reset_scan_context,
)


def _ctx(target: str, budgets: BudgetConfig | None = None):
    config = ScanConfig(target=target, budgets=budgets or BudgetConfig())
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=target, allow_remote=False)
    ctx.budgets = RequestBudget(config.budgets)
    attach_rate_limiter(ctx)
    return ctx


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    return server, thread, port


@pytest.mark.asyncio
async def test_manual_redirect_blocks_external_location():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "https://evil.example/loot")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    server, thread, port = _serve(Handler)
    base = f"http://127.0.0.1:{port}"
    ctx = _ctx(f"{base}/")
    token = bind_scan_context(ctx)
    try:
        async with open_secure_transport(ctx, follow_redirects=True, timeout=2.0) as client:
            with pytest.raises(ScopeBlockedError):
                await client.get(f"{base}/start")
    finally:
        reset_scan_context(token)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.mark.asyncio
async def test_max_response_bytes_enforced_while_streaming():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(b"x" * 50_000)

    server, thread, port = _serve(Handler)
    base = f"http://127.0.0.1:{port}"
    budgets = replace(BudgetConfig(), max_response_bytes=1024)
    ctx = _ctx(f"{base}/", budgets=budgets)
    token = bind_scan_context(ctx)
    try:
        async with open_secure_transport(ctx, timeout=2.0) as client:
            with pytest.raises(ResponseTooLargeError):
                await client.get(f"{base}/big")
    finally:
        reset_scan_context(token)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.mark.asyncio
async def test_dns_rebinding_toctou_detected(monkeypatch):
    calls = {"n": 0}

    def fake_getaddrinfo(host, *args, **kwargs):
        calls["n"] += 1
        ip = "127.0.0.1" if calls["n"] <= 3 else "127.0.0.2"
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]

    monkeypatch.setattr("magic_security.transport.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr("magic_security.scope.socket.getaddrinfo", fake_getaddrinfo)

    # Target host must match request host so scope same-origin allows the pin path.
    ctx = _ctx("http://rebinding.test:9/")
    token = bind_scan_context(ctx)
    try:
        async with open_secure_transport(ctx, timeout=0.5) as client:
            try:
                await client.get("http://rebinding.test:9/")
            except Exception:
                pass
            assert ctx.dns_pins.get("rebinding.test") == frozenset({"127.0.0.1"})
            with pytest.raises(ScopeBlockedError) as raised:
                await client.get("http://rebinding.test:9/again")
            assert raised.value.reason == "dns_rebinding_toctou"
    finally:
        reset_scan_context(token)


@pytest.mark.asyncio
async def test_crawler_does_not_double_count_request_budget():
    from magic_security.crawler import HttpCrawler

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>hi</body></html>")

    server, thread, port = _serve(Handler)
    base = f"http://127.0.0.1:{port}/"
    ctx = _ctx(base, budgets=replace(BudgetConfig(), max_total_requests=5))
    before = ctx.budgets.total_requests
    try:
        await HttpCrawler(max_pages=1, timeout=2.0).crawl(base, scan_context=ctx)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
    assert ctx.budgets.total_requests == before + 1
    assert ctx.metrics.requests == 1
