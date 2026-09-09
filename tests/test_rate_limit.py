from __future__ import annotations

import asyncio
import time

import pytest

from magic_security.config import RateConfig
from magic_security.rate_limit import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_caps_in_flight_and_spaces_requests():
    limiter = RateLimiter(
        RateConfig(
            global_concurrency=2,
            per_host_concurrency=2,
            requests_per_second=20.0,
        )
    )
    host = "127.0.0.1"
    started: list[float] = []

    async def worker() -> None:
        await limiter.acquire(host)
        started.append(time.monotonic())
        await asyncio.sleep(0.05)
        limiter.release(host)

    await asyncio.gather(*(worker() for _ in range(4)))
    assert limiter.max_observed_in_flight <= 2
    assert len(started) == 4
    # Requests should not all start at the exact same instant under rate limit.
    assert max(started) - min(started) >= 0.04


@pytest.mark.asyncio
async def test_rate_limiter_respects_cancellation():
    limiter = RateLimiter(RateConfig(global_concurrency=1, requests_per_second=100))
    cancelled = False

    await limiter.acquire("127.0.0.1")

    async def waiter() -> None:
        nonlocal cancelled
        try:
            await limiter.acquire(
                "127.0.0.1",
                cancelled=lambda: True,
            )
        except asyncio.CancelledError:
            cancelled = True

    task = asyncio.create_task(waiter())
    await asyncio.sleep(0.05)
    await task
    assert cancelled
    limiter.release("127.0.0.1")


@pytest.mark.asyncio
async def test_backoff_on_429():
    limiter = RateLimiter(RateConfig())
    assert limiter.should_backoff(429)
    assert limiter.should_backoff(503)
    assert not limiter.should_backoff(200)
    started = time.monotonic()
    await limiter.backoff(429, attempt=1)
    assert time.monotonic() - started >= 1.5
