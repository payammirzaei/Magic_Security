"""Concurrency and rate control (STEP 8)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from magic_security.config import RateConfig


@dataclass
class RateLimiter:
    config: RateConfig
    _global_sem: asyncio.Semaphore = field(init=False)
    _host_sems: dict[str, asyncio.Semaphore] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _last_request_at: float = 0.0
    _in_flight: int = 0
    max_observed_in_flight: int = 0

    def __post_init__(self) -> None:
        self._global_sem = asyncio.Semaphore(self.config.global_concurrency)

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._host_sems:
            self._host_sems[host] = asyncio.Semaphore(
                self.config.per_host_concurrency
            )
        return self._host_sems[host]

    async def acquire(
        self,
        host: str,
        *,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        while True:
            if cancelled and cancelled():
                raise asyncio.CancelledError(
                    "scan cancelled while waiting for rate slot"
                )
            acquired_global = False
            try:
                await asyncio.wait_for(self._global_sem.acquire(), timeout=0.05)
                acquired_global = True
                await asyncio.wait_for(self._host_sem(host).acquire(), timeout=0.05)
                break
            except TimeoutError:
                if acquired_global:
                    self._global_sem.release()
                await asyncio.sleep(0.01)

        async with self._lock:
            min_interval = 1.0 / max(self.config.requests_per_second, 0.1)
            now = time.monotonic()
            wait = self._last_request_at + min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()
            self._in_flight += 1
            self.max_observed_in_flight = max(
                self.max_observed_in_flight,
                self._in_flight,
            )

    def release(self, host: str) -> None:
        self._in_flight = max(0, self._in_flight - 1)
        self._host_sem(host).release()
        self._global_sem.release()

    def should_backoff(self, status_code: int) -> bool:
        return status_code in self.config.backoff_on_status

    async def backoff(self, status_code: int, attempt: int = 1) -> None:
        if not self.should_backoff(status_code):
            return
        delay = min(2.0 ** attempt, 8.0)
        await asyncio.sleep(delay)
