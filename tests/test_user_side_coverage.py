from magic_security.models import (
    SensitiveEndpointObservation,
    UserSurfaceObservation,
)
from magic_security.user_side_coverage import build_user_side_security_coverage


def test_user_side_coverage_counts_verified_surface():
    coverage = build_user_side_security_coverage(
        robots_entries=2,
        sitemap_entries=3,
        sensitive_endpoints=[
            SensitiveEndpointObservation(
                url="http://localhost/backup.zip",
                category="backup_archive",
                status_code=200,
                verified=True,
                detail="signature_matched",
            ),
            SensitiveEndpointObservation(
                url="http://localhost/phpinfo.php",
                category="runtime_debug",
                status_code=404,
                verified=False,
                detail="not_verified",
            ),
        ],
        user_surface=[
            UserSurfaceObservation(
                category="sensitive_url_parameter",
                url="http://localhost/reset",
                parameter="token",
                verified=True,
                detail="secret_like",
            ),
            UserSurfaceObservation(
                category="jsonp",
                url="http://localhost/jsonp",
                parameter="callback",
                verified=True,
                detail="arbitrary_callback_wrapping",
            ),
        ],
    )

    assert coverage.robots_entries == 2
    assert coverage.sitemap_entries == 3
    assert coverage.sensitive_endpoint_probes == 2
    assert coverage.sensitive_endpoint_verified == 1
    assert coverage.sensitive_url_parameters == 1
    assert coverage.jsonp_exposed == 1
