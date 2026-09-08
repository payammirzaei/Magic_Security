from __future__ import annotations

from magic_security.models import AuthContext, CsrfCandidate, NormalizedEndpoint


_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_NAMES = {
    "csrf",
    "csrf_token",
    "csrftoken",
    "xsrf",
    "xsrf_token",
    "_token",
    "authenticity_token",
}


def _has_csrf_signal(parameters: tuple[str, ...]) -> bool:
    lowered = {item.lower() for item in parameters}
    if lowered & _CSRF_NAMES:
        return True
    return any("csrf" in item or "xsrf" in item for item in lowered)


def _auth_style(contexts: list[AuthContext]) -> str:
    has_cookie = any(bool(context.cookies) for context in contexts)
    has_header = any(
        any(
            key.lower() in {"authorization", "x-api-key", "x-auth-token"}
            for key in context.headers
        )
        for context in contexts
    )

    if has_cookie and has_header:
        return "mixed"
    if has_cookie:
        return "cookie"
    if has_header:
        return "header"
    return "unknown"


def map_csrf_posture(
    endpoints: list[NormalizedEndpoint],
    contexts: list[AuthContext],
) -> list[CsrfCandidate]:
    style = _auth_style(contexts)
    candidates: list[CsrfCandidate] = []

    for endpoint in endpoints:
        if endpoint.method.upper() not in _STATE_CHANGING:
            continue

        token_signal = _has_csrf_signal(endpoint.parameters)

        if style == "header":
            posture = "header_authenticated"
        elif token_signal:
            posture = "token_signal_present"
        elif style in {"cookie", "mixed"}:
            posture = "cookie_authenticated_needs_verification"
        else:
            posture = "auth_mechanism_unknown"

        candidates.append(
            CsrfCandidate(
                url=endpoint.url,
                method=endpoint.method.upper(),
                parameters=endpoint.parameters,
                auth_style=style,
                token_signal_present=token_signal,
                posture=posture,
            )
        )

    return sorted(candidates, key=lambda item: (item.url, item.method))
