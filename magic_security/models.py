from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingKind(str, Enum):
    VULNERABILITY = "vulnerability"
    EXPOSURE = "exposure"
    HARDENING = "hardening"


@dataclass(slots=True)
class PageSnapshot:
    url: str
    status_code: int
    headers: dict[str, str]
    set_cookies: list[str]
    content_type: str
    body: str


@dataclass(slots=True)
class CrawlResult:
    target: str
    pages: list[PageSnapshot] = field(default_factory=list)
    links: set[str] = field(default_factory=set)
    js_assets: set[str] = field(default_factory=set)
    forms: list[dict[str, str]] = field(default_factory=list)


@dataclass(slots=True)
class Finding:
    title: str
    severity: Severity
    kind: FindingKind
    url: str
    description: str
    evidence: str
    remediation: str
    confidence: float = 1.0
    owasp: str | None = None
    cwe: str | None = None

    @property
    def verified(self) -> bool:
        return self.confidence >= 0.95
