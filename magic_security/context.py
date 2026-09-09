"""Per-scan runtime context (STEP 5)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from magic_security.config import ScanConfig
from magic_security.models import AuthContext


@dataclass
class ScanMetrics:
    requests: int = 0
    pages: int = 0
    active_mutations: int = 0
    browser_navigations: int = 0
    budget_exhausted: bool = False
    notes: list[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        self.notes.append(message)


@dataclass
class ScanContext:
    config: ScanConfig
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    cancelled: bool = False
    metrics: ScanMetrics = field(default_factory=ScanMetrics)
    scope: Any = None
    budgets: Any = None
    transport: Any = None
    redactor: Any = None

    @property
    def target(self) -> str:
        return self.config.target

    @property
    def auth_contexts(self) -> tuple[AuthContext, ...]:
        return tuple(self.config.auth_contexts)

    def cancel(self) -> None:
        self.cancelled = True

    def is_cancelled(self) -> bool:
        return self.cancelled


def create_scan_context(config: ScanConfig) -> ScanContext:
    return ScanContext(config=config)
