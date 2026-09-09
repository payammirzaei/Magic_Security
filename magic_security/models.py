from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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


class ConfidenceLevel(str, Enum):
    CANDIDATE = "candidate"
    LIKELY = "likely"
    STRONG = "strong"
    VERIFIED = "verified"


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
    login_mechanism: str | None = None
    browser_state: dict[str, Any] | None = None
    expected_identity_marker: str | None = None
    disposable: bool = False


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


@dataclass(frozen=True, slots=True)
class InjectionObservation:
    url: str
    parameter: str
    raw_reflected: bool
    html_injection_verified: bool
    script_execution_verified: bool


@dataclass(frozen=True, slots=True)
class GraphqlObservation:
    url: str
    status_code: int
    anonymous_introspection: bool
    detailed_errors: bool


@dataclass(frozen=True, slots=True)
class ClientArtifactObservation:
    url: str
    artifact_type: str
    secret_like_names: tuple[str, ...]
    token_shapes: tuple[str, ...]
    internal_url_count: int


@dataclass(frozen=True, slots=True)
class CorsImpactObservation:
    url: str
    context: str
    status_code: int
    origin_reflected: bool
    credentials_allowed: bool
    protected_response_exposed: bool


@dataclass(frozen=True, slots=True)
class CacheObservation:
    url: str
    context: str
    cache_control: str
    risky_shared_cache: bool


@dataclass(frozen=True, slots=True)
class RateLimitObservation:
    url: str
    method: str
    requests_sent: int
    statuses: tuple[int, ...]
    throttled: bool
    rate_limit_headers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ParameterSecurityObservation:
    url: str
    parameter: str
    category: str
    verified: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ProtocolSecurityObservation:
    category: str
    method: str
    status_code: int
    detail: str


@dataclass(frozen=True, slots=True)
class SensitiveEndpointObservation:
    url: str
    category: str
    status_code: int
    verified: bool
    detail: str


@dataclass(frozen=True, slots=True)
class UserSurfaceObservation:
    category: str
    url: str
    parameter: str | None
    verified: bool
    detail: str


@dataclass(frozen=True, slots=True)
class UserSideSecurityCoverage:
    robots_entries: int = 0
    sitemap_entries: int = 0
    sensitive_endpoint_probes: int = 0
    sensitive_endpoint_verified: int = 0
    sensitive_url_parameters: int = 0
    sensitive_get_forms: int = 0
    mixed_content_pages: int = 0
    null_origin_cors_exposed: int = 0
    jsonp_exposed: int = 0


@dataclass(frozen=True, slots=True)
class ExternalSecurityCoverage:
    injection_tests: int = 0
    html_injection_verified: int = 0
    xss_execution_verified: int = 0
    graphql_endpoints_tested: int = 0
    graphql_introspection_exposed: int = 0
    graphql_detailed_errors: int = 0
    client_artifacts_scanned: int = 0
    secret_like_artifacts: int = 0
    internal_topology_artifacts: int = 0
    protected_cors_tests: int = 0
    protected_cors_exposed: int = 0
    authenticated_cache_tests: int = 0
    risky_shared_cache: int = 0
    rate_limit_endpoints_tested: int = 0
    rate_limit_throttled: int = 0
    parameter_security_tests: int = 0
    database_error_triggers: int = 0
    ssti_verified: int = 0
    crlf_verified: int = 0
    parameter_pollution_observations: int = 0
    protocol_observations: int = 0


@dataclass(frozen=True, slots=True)
class BrowserSecurityObservation:
    category: str
    url: str
    status: str
    evidence: str
    context: str | None = None


@dataclass(frozen=True, slots=True)
class BrowserSecurityCoverage:
    artifacts_scanned: int = 0
    dom_source_sink_candidates: int = 0
    dom_xss_verified: int = 0
    message_handlers: int = 0
    message_handlers_missing_origin: int = 0
    client_redirect_candidates: int = 0
    sensitive_storage_keys: int = 0
    websocket_endpoints: int = 0


@dataclass(frozen=True, slots=True)
class ServerProbeObservation:
    category: str
    url: str
    parameter: str
    status_code: int
    verified: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ServerSecurityCoverage:
    total_probes: int = 0
    database_error_triggers: int = 0
    ssti_verified: int = 0
    crlf_verified: int = 0
    path_traversal_verified: int = 0
    ssrf_verified: int = 0
    auth_sqli_verified: int = 0
    auth_nosqli_verified: int = 0
    host_header_influences: int = 0


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

    injection_observations: list[InjectionObservation] = field(default_factory=list)
    graphql_observations: list[GraphqlObservation] = field(default_factory=list)
    client_artifact_observations: list[ClientArtifactObservation] = field(default_factory=list)
    cors_impact_observations: list[CorsImpactObservation] = field(default_factory=list)
    cache_observations: list[CacheObservation] = field(default_factory=list)
    rate_limit_observations: list[RateLimitObservation] = field(default_factory=list)
    parameter_security_observations: list[ParameterSecurityObservation] = field(default_factory=list)
    protocol_security_observations: list[ProtocolSecurityObservation] = field(default_factory=list)
    coverage_registry: list[dict[str, str]] = field(default_factory=list)
    external_security_coverage: ExternalSecurityCoverage | None = None

    sensitive_endpoint_observations: list[SensitiveEndpointObservation] = field(default_factory=list)
    user_surface_observations: list[UserSurfaceObservation] = field(default_factory=list)
    index_robots_entries: int = 0
    index_sitemap_entries: int = 0
    user_side_security_coverage: UserSideSecurityCoverage | None = None

    browser_security_observations: list[BrowserSecurityObservation] = field(default_factory=list)
    browser_security_coverage: BrowserSecurityCoverage | None = None
    websocket_endpoints: set[str] = field(default_factory=set)

    server_security_observations: list[ServerProbeObservation] = field(default_factory=list)
    server_security_coverage: ServerSecurityCoverage | None = None

    parameters: set[str] = field(default_factory=set)
    source_maps: set[str] = field(default_factory=set)
    browser_pages: set[str] = field(default_factory=set)
    browser_network_requests: int = 0
    authenticated_browser_pages: dict[str, set[str]] = field(default_factory=dict)
    authenticated_browser_network_requests: dict[str, int] = field(default_factory=dict)
    response_groups: dict[str, tuple[str, ...]] = field(default_factory=dict)
    budget_coverage: dict[str, object] = field(default_factory=dict)
    attack_surface_graph: dict[str, object] = field(default_factory=dict)
    historical_endpoints: list[NormalizedEndpoint] = field(default_factory=list)
    check_coverage: list[dict[str, str]] = field(default_factory=list)
    pack_failures: list[dict[str, str]] = field(default_factory=list)
    scan_metrics: dict[str, object] = field(default_factory=dict)
    js_analysis: list[dict[str, object]] = field(default_factory=list)
    pack_coverage: dict[str, object] = field(default_factory=dict)
    authz_matrix: list[dict[str, object]] = field(default_factory=list)
    identity_validation: dict[str, object] = field(default_factory=dict)
    repo_findings: list[dict[str, object]] = field(default_factory=list)
    repo_snapshot: dict[str, object] = field(default_factory=dict)
    repo_correlations: list[dict[str, object]] = field(default_factory=list)


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
    check_id: str | None = None
    fingerprint: str | None = None
    structured_evidence: dict | None = None

    @property
    def confidence_level(self) -> ConfidenceLevel:
        if self.confidence >= 0.95:
            return ConfidenceLevel.VERIFIED
        if self.confidence >= 0.80:
            return ConfidenceLevel.STRONG
        if self.confidence >= 0.50:
            return ConfidenceLevel.LIKELY
        return ConfidenceLevel.CANDIDATE

    @property
    def verified(self) -> bool:
        return self.confidence_level is ConfidenceLevel.VERIFIED
