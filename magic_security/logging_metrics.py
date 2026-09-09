"""Structured scanner logging and metrics (STEP 15)."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from magic_security.redaction import Redactor


@dataclass
class ScanMetricsAggregate:
    requests: int = 0
    pages: int = 0
    endpoints: int = 0
    checks_executed: int = 0
    verified_findings: int = 0
    pack_durations_ms: dict[str, float] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "pages": self.pages,
            "endpoints": self.endpoints,
            "checks_executed": self.checks_executed,
            "verified_findings": self.verified_findings,
            "pack_durations_ms": dict(self.pack_durations_ms),
            "event_count": len(self.events),
        }


class StructuredLogger:
    def __init__(self, *, redactor: Redactor | None = None) -> None:
        self.redactor = redactor or Redactor()
        self.metrics = ScanMetricsAggregate()
        self._pack_started: dict[str, float] = {}

    def _emit(self, event: str, **payload: Any) -> dict[str, Any]:
        record = {
            "event": event,
            "ts": time.time(),
            **payload,
        }
        scrubbed = self.redactor.scrub_structure(record)
        self.metrics.events.append(scrubbed)
        return scrubbed

    def scan_start(self, target: str, modes: dict[str, Any]) -> None:
        self._emit("scan_start", target=target, modes=modes)

    def scan_end(self, *, findings: int, duration_ms: float) -> None:
        self._emit(
            "scan_end",
            findings=findings,
            duration_ms=duration_ms,
            metrics=self.metrics.to_dict(),
        )

    def discovery_phase(self, phase: str, **payload: Any) -> None:
        self._emit("discovery_phase", phase=phase, **payload)

    def pack_start(self, pack: str) -> None:
        self._pack_started[pack] = time.perf_counter()
        self._emit("pack_start", pack=pack)

    def pack_end(self, pack: str, *, findings: int = 0) -> None:
        started = self._pack_started.pop(pack, None)
        duration = (
            (time.perf_counter() - started) * 1000.0 if started is not None else 0.0
        )
        self.metrics.pack_durations_ms[pack] = duration
        self._emit(
            "pack_end",
            pack=pack,
            findings=findings,
            duration_ms=duration,
        )

    def budget_use(self, **payload: Any) -> None:
        self._emit("request_budget_use", **payload)

    def scope_denial(self, url: str, reason: str) -> None:
        self._emit("scope_denial", url=url, reason=reason)

    def timeout(self, check_id: str, timeout: float) -> None:
        self._emit("timeout", check_id=check_id, timeout=timeout)

    def check_error(self, check_id: str, error: str) -> None:
        self._emit("check_error", check_id=check_id, error=error)

    def finding_emitted(self, check_id: str | None, title: str, verified: bool) -> None:
        if verified:
            self.metrics.verified_findings += 1
        self._emit(
            "finding_emitted",
            check_id=check_id,
            title=title,
            verified=verified,
        )

    def coverage_degradation(self, reasons: list[str]) -> None:
        self._emit("coverage_degradation", reasons=reasons)

    def dumps(self) -> str:
        return json.dumps(self.metrics.events, ensure_ascii=False)
