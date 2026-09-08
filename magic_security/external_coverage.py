from __future__ import annotations

from magic_security.models import (
    CacheObservation,
    ClientArtifactObservation,
    CorsImpactObservation,
    ExternalSecurityCoverage,
    GraphqlObservation,
    InjectionObservation,
    RateLimitObservation,
)


def build_external_security_coverage(
    injection: list[InjectionObservation],
    graphql: list[GraphqlObservation],
    artifacts: list[ClientArtifactObservation],
    cors: list[CorsImpactObservation],
    cache: list[CacheObservation],
    rate_limits: list[RateLimitObservation],
) -> ExternalSecurityCoverage:
    return ExternalSecurityCoverage(
        injection_tests=len(injection),
        html_injection_verified=sum(
            1 for item in injection if item.html_injection_verified
        ),
        xss_execution_verified=sum(
            1 for item in injection if item.script_execution_verified
        ),
        graphql_endpoints_tested=len(graphql),
        graphql_introspection_exposed=sum(
            1 for item in graphql if item.anonymous_introspection
        ),
        graphql_detailed_errors=sum(
            1 for item in graphql if item.detailed_errors
        ),
        client_artifacts_scanned=len(artifacts),
        secret_like_artifacts=sum(
            1
            for item in artifacts
            if item.secret_like_names or item.token_shapes
        ),
        internal_topology_artifacts=sum(
            1 for item in artifacts if item.internal_url_count > 0
        ),
        protected_cors_tests=len(cors),
        protected_cors_exposed=sum(
            1 for item in cors if item.protected_response_exposed
        ),
        authenticated_cache_tests=len(cache),
        risky_shared_cache=sum(
            1 for item in cache if item.risky_shared_cache
        ),
        rate_limit_endpoints_tested=len(rate_limits),
        rate_limit_throttled=sum(
            1 for item in rate_limits if item.throttled
        ),
    )
