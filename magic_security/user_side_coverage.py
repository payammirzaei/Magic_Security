from __future__ import annotations

from magic_security.models import (
    SensitiveEndpointObservation,
    UserSideSecurityCoverage,
    UserSurfaceObservation,
)


def build_user_side_security_coverage(
    *,
    robots_entries: int,
    sitemap_entries: int,
    sensitive_endpoints: list[SensitiveEndpointObservation],
    user_surface: list[UserSurfaceObservation],
) -> UserSideSecurityCoverage:
    return UserSideSecurityCoverage(
        robots_entries=robots_entries,
        sitemap_entries=sitemap_entries,
        sensitive_endpoint_probes=len(sensitive_endpoints),
        sensitive_endpoint_verified=sum(
            1 for item in sensitive_endpoints if item.verified
        ),
        sensitive_url_parameters=sum(
            1
            for item in user_surface
            if item.category == "sensitive_url_parameter"
            and item.verified
        ),
        sensitive_get_forms=sum(
            1
            for item in user_surface
            if item.category == "sensitive_get_form"
            and item.verified
        ),
        mixed_content_pages=sum(
            1
            for item in user_surface
            if item.category == "mixed_content"
            and item.verified
        ),
        null_origin_cors_exposed=sum(
            1
            for item in user_surface
            if item.category == "null_origin_cors"
            and item.verified
        ),
        jsonp_exposed=sum(
            1
            for item in user_surface
            if item.category == "jsonp"
            and item.verified
        ),
    )
