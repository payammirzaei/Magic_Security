from __future__ import annotations

from magic_security.models import (
    AuthComparison,
    AuthSecurityCoverage,
    CsrfCandidate,
    NormalizedEndpoint,
    OwnershipObservation,
    PairwiseIdorObservation,
    SessionCookieObservation,
)


def build_auth_security_coverage(
    endpoints: list[NormalizedEndpoint],
    auth_comparisons: list[AuthComparison],
    ownership: list[OwnershipObservation],
    idor_observations: list[PairwiseIdorObservation],
    csrf_candidates: list[CsrfCandidate],
    session_cookies: list[SessionCookieObservation],
) -> AuthSecurityCoverage:
    state_changing = {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    return AuthSecurityCoverage(
        total_endpoints=len(endpoints),
        read_endpoints=sum(
            1 for item in endpoints if item.method.upper() == "GET"
        ),
        state_changing_endpoints=sum(
            1
            for item in endpoints
            if item.method.upper() in state_changing
        ),
        auth_compared_endpoints=len(auth_comparisons),
        protected_endpoints=sum(
            1
            for item in auth_comparisons
            if item.boundary == "protected"
        ),
        public_or_unprotected_endpoints=sum(
            1
            for item in auth_comparisons
            if item.boundary == "public_or_unprotected"
        ),
        user_specific_endpoints=sum(
            1
            for item in auth_comparisons
            if item.authenticated_responses_differ
        ),
        ownership_signals=len(ownership),
        idor_pairwise_tests=len(idor_observations),
        idor_verified=sum(
            1
            for item in idor_observations
            if item.cross_account_verified
        ),
        csrf_state_changing_candidates=len(csrf_candidates),
        csrf_needs_verification=sum(
            1
            for item in csrf_candidates
            if item.posture == "cookie_authenticated_needs_verification"
        ),
        session_cookies_observed=len(session_cookies),
        weak_session_cookie_observations=sum(
            1
            for item in session_cookies
            if item.auth_like
            and (
                not item.httponly
                or item.same_site is None
                or (item.same_site == "none" and not item.secure)
            )
        ),
    )
