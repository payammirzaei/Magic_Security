from __future__ import annotations

from magic_security.models import (
    ParameterSecurityObservation,
    ServerProbeObservation,
    ServerSecurityCoverage,
)


def build_server_security_coverage(
    parameter_security: list[ParameterSecurityObservation],
    server_security: list[ServerProbeObservation],
) -> ServerSecurityCoverage:
    def parameter_verified(category: str) -> int:
        return sum(
            1
            for item in parameter_security
            if item.category == category and item.verified
        )

    def server_verified(category: str) -> int:
        return sum(
            1
            for item in server_security
            if item.category == category and item.verified
        )

    return ServerSecurityCoverage(
        total_probes=(
            len(parameter_security)
            + len(server_security)
        ),
        database_error_triggers=parameter_verified(
            "database_error"
        ),
        ssti_verified=parameter_verified("ssti"),
        crlf_verified=parameter_verified(
            "crlf_header_injection"
        ),
        path_traversal_verified=server_verified(
            "path_traversal"
        ),
        ssrf_verified=server_verified("ssrf"),
        auth_sqli_verified=server_verified("auth_sqli"),
        auth_nosqli_verified=server_verified(
            "auth_nosqli"
        ),
        host_header_influences=server_verified(
            "host_header"
        ),
    )
