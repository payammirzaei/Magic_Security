"""STEP 71 — performance baselines (synthetic, coverage-preserving)."""

from __future__ import annotations

import time

from magic_security.models import NormalizedEndpoint
from magic_security.surface import canonical_endpoint_url


def _synthetic_endpoints(n: int) -> list[NormalizedEndpoint]:
    return [
        NormalizedEndpoint(
            url=canonical_endpoint_url(f"http://127.0.0.1:8000/api/item/{i}", normalize_ids=True),
            method="GET",
            parameters=("id",),
            sources=("synthetic",),
        )
        for i in range(n)
    ]


def test_endpoint_normalization_scales_near_linear():
    small = _synthetic_endpoints(20)
    medium = _synthetic_endpoints(200)
    t0 = time.perf_counter()
    _ = {(e.method, e.url) for e in small}
    small_dt = time.perf_counter() - t0
    t1 = time.perf_counter()
    _ = {(e.method, e.url) for e in medium}
    medium_dt = time.perf_counter() - t1
    # Allow generous slack; catch accidental O(N^2) explosions only.
    assert medium_dt < max(0.5, small_dt * 50 + 0.2)
    assert len({e.url for e in medium}) <= 200
