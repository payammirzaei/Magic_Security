from magic_security.csrf import map_csrf_posture
from magic_security.models import AuthContext, NormalizedEndpoint


def test_cookie_authenticated_state_change_without_token_is_candidate():
    result = map_csrf_posture(
        [
            NormalizedEndpoint(
                url="http://localhost/api/profile",
                method="POST",
                parameters=("display_name",),
            )
        ],
        [
            AuthContext(
                name="user_a",
                cookies={"session": "fake"},
            )
        ],
    )

    assert len(result) == 1
    assert result[0].posture == "cookie_authenticated_needs_verification"
    assert result[0].token_signal_present is False


def test_csrf_token_signal_is_recognized():
    result = map_csrf_posture(
        [
            NormalizedEndpoint(
                url="http://localhost/api/profile",
                method="POST",
                parameters=("display_name", "csrf_token"),
            )
        ],
        [AuthContext(name="user_a", cookies={"session": "fake"})],
    )

    assert result[0].posture == "token_signal_present"


def test_header_auth_is_not_promoted_to_csrf_candidate():
    result = map_csrf_posture(
        [
            NormalizedEndpoint(
                url="http://localhost/api/profile",
                method="PATCH",
                parameters=("display_name",),
            )
        ],
        [
            AuthContext(
                name="user_a",
                headers={"Authorization": "Bearer fake"},
            )
        ],
    )

    assert result[0].posture == "header_authenticated"
