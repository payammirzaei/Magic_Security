from magic_security.external_coverage import build_external_security_coverage
from magic_security.models import (
    CacheObservation,
    ClientArtifactObservation,
    CorsImpactObservation,
    GraphqlObservation,
    InjectionObservation,
    RateLimitObservation,
)


def test_external_coverage_counts_verified_surfaces():
    coverage = build_external_security_coverage(
        [
            InjectionObservation(
                url="http://localhost/search",
                parameter="q",
                raw_reflected=True,
                html_injection_verified=True,
                script_execution_verified=True,
            )
        ],
        [
            GraphqlObservation(
                url="http://localhost/graphql",
                status_code=200,
                anonymous_introspection=True,
                detailed_errors=False,
            )
        ],
        [
            ClientArtifactObservation(
                url="http://localhost/app.js",
                artifact_type="javascript",
                secret_like_names=("API_SECRET",),
                token_shapes=(),
                internal_url_count=1,
            )
        ],
        [
            CorsImpactObservation(
                url="http://localhost/api/me",
                context="user_a",
                status_code=200,
                origin_reflected=True,
                credentials_allowed=True,
                protected_response_exposed=True,
            )
        ],
        [
            CacheObservation(
                url="http://localhost/api/me",
                context="user_a",
                cache_control="public, max-age=60",
                risky_shared_cache=True,
            )
        ],
        [
            RateLimitObservation(
                url="http://localhost/api/public",
                method="GET",
                requests_sent=4,
                statuses=(200, 200, 200, 429),
                throttled=True,
                rate_limit_headers=("retry-after",),
            )
        ],
    )

    assert coverage.xss_execution_verified == 1
    assert coverage.graphql_introspection_exposed == 1
    assert coverage.secret_like_artifacts == 1
    assert coverage.protected_cors_exposed == 1
    assert coverage.risky_shared_cache == 1
    assert coverage.rate_limit_throttled == 1
