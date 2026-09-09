from __future__ import annotations

import asyncio

import pytest

from magic_security.config import ScanConfig
from magic_security.context import create_scan_context
from magic_security.engine import ScannerEngine


def test_scan_contexts_are_isolated():
    first = create_scan_context(ScanConfig(target="http://127.0.0.1:8000"))
    second = create_scan_context(ScanConfig(target="http://127.0.0.1:8001"))
    assert first.scan_id != second.scan_id
    first.metrics.requests = 3
    assert second.metrics.requests == 0
    first.cancel()
    assert first.is_cancelled()
    assert not second.is_cancelled()


@pytest.mark.asyncio
async def test_engine_creates_distinct_contexts_per_scan():
    engine = ScannerEngine(max_pages=1)
    contexts: list[str] = []

    original = engine._scan_body

    async def capture(context, **kwargs):
        contexts.append(context.scan_id)
        return await original(context, **kwargs)

    engine._scan_body = capture  # type: ignore[method-assign]

    # Both should fail remote gate before body — use loopback with unreachable port
    # so we exercise context creation. Use allow_remote false with example.com.
    with pytest.raises(ValueError):
        await engine.scan("http://example.com")

    # Context is created after local check — verify via successful path mock
    config_a = ScanConfig(target="http://127.0.0.1:1", max_pages=1)
    config_b = ScanConfig(target="http://127.0.0.1:1", max_pages=1)

    await asyncio.gather(
        engine.scan(config=config_a),
        engine.scan(config=config_b),
    )
    assert len(contexts) == 2
    assert contexts[0] != contexts[1]
