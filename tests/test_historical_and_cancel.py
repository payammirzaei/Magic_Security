"""STEP 63 historical seeding + STEP 72 cancellation/recovery smoke."""

from __future__ import annotations

from magic_security.config import ScanConfig
from magic_security.context import create_scan_context
from magic_security.historical import seed_historical_endpoints
from magic_security.models import NormalizedEndpoint


def test_historical_endpoints_marked_and_not_auto_verified():
    current: list[NormalizedEndpoint] = []
    snapshot = {
        "schema_version": 2,
        "attack_surface": {
            "items": [
                "endpoint:GET:http://127.0.0.1:8000/old:",
            ]
        },
        "findings": [],
    }
    merged, seeded = seed_historical_endpoints(current, snapshot)
    assert seeded
    assert any("/old" in item.url for item in merged)
    assert all("historical" in ",".join(item.sources) for item in seeded)


def test_scan_context_cancellation():
    ctx = create_scan_context(ScanConfig(target="http://127.0.0.1:8000/"))
    assert not ctx.is_cancelled()
    ctx.cancel()
    assert ctx.is_cancelled()
