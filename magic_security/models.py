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


@dataclass(frozen=True, slots=True)
class EndpointCandidate:
    url: str
    method: str = "GET"
    source: str = "discovery"
    parameters: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NormalizedEndpoint:
    url: str
    method: str = "GET"
    parameters: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EndpointObservation:
    url: str
    method: str
    status_code: int
    classification: str
    content_type: str
    sensitive_fields: tuple[str, ...] = ()
    secret_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthContext:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuthComparison:
    url: str
    method: str
    boundary: str
    anonymous_status: int | None
    context_statuses: tuple[tuple[str, int], ...] = ()
    authenticated_responses_differ: bool = False


@dataclass(slots=True)
class CrawlResult:
    target: str
    pages: list[PageSnapshot] = field(default_factory=list)
    links: set[str] = field(default_factory=set)
    js_assets: set[str] = field(default_factory=set)
    forms: list[dict[str, str]] = field(default_factory=list)
    endpoints: set[EndpointCandidate] = field(default_factory=set)
    normalized_endpoints: list[NormalizedEndpoint] = field(default_factory=list)
    endpoint_observations: list[EndpointObservation] = field(default_factory=list)
    auth_comparisons: list[AuthComparison] = field(default_factory=list)
    parameters: set[str] = field(default_factory=set)
    source_maps: set[str] = field(default_factory=set)
    browser_pages: set[str] = field(default_factory=set)
    browser_network_requests: int = 0
    response_groups: dict[str, tuple[str, ...]] = field(default_factory=dict)


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
    affected_urls: tuple[str, ...] = ()
    occurrences: int = 1
    fingerprint: str | None = None

    @property
    def verified(self) -> bool:
        return self.confidence >= 0.95
