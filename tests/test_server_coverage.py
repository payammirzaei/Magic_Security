from magic_security.models import (
    ParameterSecurityObservation,
    ServerProbeObservation,
)
from magic_security.server_coverage import build_server_security_coverage


def test_server_coverage_combines_parameter_and_server_probes():
    parameter_observations = [
        ParameterSecurityObservation(
            url="http://localhost/search",
            parameter="q",
            category="database_error",
            verified=True,
            detail="database error signature triggered",
        ),
        ParameterSecurityObservation(
            url="http://localhost/template",
            parameter="name",
            category="ssti",
            verified=True,
            detail="template arithmetic evaluated",
        ),
    ]
    server_observations = [
        ServerProbeObservation(
            category="path_traversal",
            url="http://localhost/download",
            parameter="file",
            status_code=200,
            verified=True,
            detail="unix_hosts",
        ),
        ServerProbeObservation(
            category="ssrf",
            url="http://localhost/fetch",
            parameter="url",
            status_code=200,
            verified=False,
            detail="no_callback_received",
        ),
    ]

    coverage = build_server_security_coverage(
        parameter_observations,
        server_observations,
    )

    assert coverage.total_probes == 4
    assert coverage.database_error_triggers == 1
    assert coverage.ssti_verified == 1
    assert coverage.path_traversal_verified == 1
    assert coverage.ssrf_verified == 0
