from magic_security.coverage import build_auth_security_coverage
from magic_security.models import (
    AuthComparison,
    CsrfCandidate,
    NormalizedEndpoint,
    OwnershipObservation,
    PairwiseIdorObservation,
    SessionCookieObservation,
)


def test_auth_security_coverage_counts_major_areas():
    endpoints = [
        NormalizedEndpoint(url="http://localhost/api/me", method="GET"),
        NormalizedEndpoint(url="http://localhost/api/profile", method="POST"),
    ]
    comparisons = [
        AuthComparison(
            url="http://localhost/api/me",
            method="GET",
            boundary="protected",
            anonymous_status=401,
            context_statuses=(("user_a", 200), ("user_b", 200)),
            authenticated_responses_differ=True,
        )
    ]
    ownership = [
        OwnershipObservation(
            context="user_a",
            parameter="account_id",
            discovered_values=1,
            source_endpoints=("http://localhost/api/me",),
        )
    ]
    idor = [
        PairwiseIdorObservation(
            endpoint="http://localhost/api/accounts/{account_id}",
            parameter="account_id",
            parameter_location="path",
            owner_context="user_a",
            requester_context="user_b",
            owner_status=200,
            requester_status=200,
            cross_account_verified=True,
        )
    ]
    csrf = [
        CsrfCandidate(
            url="http://localhost/api/profile",
            method="POST",
            parameters=("display_name",),
            auth_style="cookie",
            token_signal_present=False,
            posture="cookie_authenticated_needs_verification",
        )
    ]
    sessions = [
        SessionCookieObservation(
            context="user_a",
            source_url="http://localhost/dashboard",
            cookie_name="demo_session",
            auth_like=True,
            secure=False,
            httponly=False,
            same_site=None,
        )
    ]

    result = build_auth_security_coverage(
        endpoints,
        comparisons,
        ownership,
        idor,
        csrf,
        sessions,
    )

    assert result.total_endpoints == 2
    assert result.state_changing_endpoints == 1
    assert result.protected_endpoints == 1
    assert result.user_specific_endpoints == 1
    assert result.idor_verified == 1
    assert result.csrf_needs_verification == 1
    assert result.weak_session_cookie_observations == 1
