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
    role: str | None = None


@dataclass(frozen=True, slots=True)
class AuthComparison:
    url: str
    method: str
    boundary: str
    anonymous_status: int | None
    context_statuses: tuple[tuple[str, int], ...] = ()
    authenticated_responses_differ: bool = False


@dataclass(frozen=True, slots=True)
class IdorObservation:
    endpoint_template: str
    parameter: str
    user_a_own_status: int
    user_b_own_status: int
    user_b_to_a_status: int
    user_a_to_b_status: int
    cross_account_verified: bool
    parameter_location: str = "path"


@dataclass(frozen=True, slots=True)
class PairwiseIdorObservation:
    endpoint: str
    parameter: str
    parameter_location: str
    owner_context: str
    requester_context: str
    owner_status: int
    requester_status: int
    cross_account_verified: bool


@dataclass(frozen=True, slots=True)
class OwnershipObservation:
    context: str
    parameter: str
    discovered_values: int
    source_endpoints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SessionCookieObservation:
    context: str
    source_url: str
    cookie_name: str
    auth_like: bool
    secure: bool
    httponly: bool
    same_site: str | None


@dataclass(frozen=True, slots=True)
class CsrfCandidate:
    url: str
    method: str
    parameters: tuple[str, ...]
    auth_style: str
    token_signal_present: bool
    posture: str


@dataclass(frozen=True, slots=True)
class AuthSecurityCoverage:
    total_endpoints: int = 0
    read_endpoints: int = 0
    state_changing_endpoints: int = 0
    auth_compared_endpoints: int = 0
    protected_endpoints: int = 0
    public_or_unprotected_endpoints: int = 0
    user_specific_endpoints: int = 0
    ownership_signals: int = 0
    idor_pairwise_tests: int = 0
    idor_verified: int = 0
    csrf_state_changing_candidates: int = 0
    csrf_needs_verification: int = 0
    session_cookies_observed: int = 0
    weak_session_cookie_observations: int = 0


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
    idor_observations: list[IdorObservation] = field(default_factory=list)
    pairwise_idor_observations: list[PairwiseIdorObservation] = field(default_factory=list)
    ownership_observations: list[OwnershipObservation] = field(default_factory=list)
    session_cookie_observations: list[SessionCookieObservation] = field(default_factory=list)
    csrf_candidates: list[CsrfCandidate] = field(default_factory=list)
    auth_security_coverage: AuthSecurityCoverage | None = None
    parameters: set[str] = field(default_factory=set)
    source_maps: set[str] = field(default_factory=set)
    browser_pages: set[str] = field(default_factory=set)
    browser_network_requests: int = 0
    authenticated_browser_pages: dict[str, set[str]] = field(default_factory=dict)
    authenticated_browser_network_requests: dict[str, int] = field(default_factory=dict)
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
