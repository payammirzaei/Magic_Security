from __future__ import annotations

import re

import httpx

from magic_security.transport import open_secure_transport

from magic_security.models import (
    AuthContext,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    SessionCookieObservation,
    Severity,
)


_AUTH_COOKIE_RE = re.compile(
    r"(session|sess|sid|auth|token|jwt|connect\.sid|laravel_session)",
    re.IGNORECASE,
)


def _cookie_attributes(raw: str) -> tuple[str, bool, bool, str | None]:
    first, *parts = [part.strip() for part in raw.split(";")]
    name = first.split("=", 1)[0].strip() or "<unknown>"
    lower_parts = [part.lower() for part in parts]

    secure = "secure" in lower_parts
    httponly = "httponly" in lower_parts
    same_site: str | None = None

    for part in lower_parts:
        if part.startswith("samesite="):
            same_site = part.split("=", 1)[1].strip().lower() or None
            break

    return name, secure, httponly, same_site


async def analyze_session_cookies(
    endpoints: list[NormalizedEndpoint],
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
    max_endpoints: int = 20,
) -> tuple[list[SessionCookieObservation], list[Finding]]:
    observations: list[SessionCookieObservation] = []
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    ][:max_endpoints]

    for context in contexts:
        async with open_secure_transport(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.8 local-security-scanner",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.5",
                **context.headers,
            },
            cookies=context.cookies,
        ) as client:
            for endpoint in candidates:
                try:
                    response = await client.get(endpoint.url)
                except httpx.HTTPError:
                    continue

                for raw_cookie in response.headers.get_list("set-cookie"):
                    name, secure, httponly, same_site = _cookie_attributes(raw_cookie)
                    key = (context.name, endpoint.url, name)
                    if key in seen:
                        continue
                    seen.add(key)

                    auth_like = bool(_AUTH_COOKIE_RE.search(name))
                    observation = SessionCookieObservation(
                        context=context.name,
                        source_url=endpoint.url,
                        cookie_name=name,
                        auth_like=auth_like,
                        secure=secure,
                        httponly=httponly,
                        same_site=same_site,
                    )
                    observations.append(observation)

                    if not auth_like:
                        continue

                    missing: list[str] = []
                    if not httponly:
                        missing.append("HttpOnly")
                    if same_site is None:
                        missing.append("SameSite")
                    if same_site == "none" and not secure:
                        missing.append("Secure (required with SameSite=None)")

                    if not missing:
                        continue

                    findings.append(
                        Finding(
                            title=f"Session-like cookie {name} lacks protective attributes",
                            severity=Severity.LOW,
                            kind=FindingKind.HARDENING,
                            url=endpoint.url,
                            description=(
                                "An authenticated response set a session-like cookie "
                                "without all expected browser-side protections."
                            ),
                            evidence=(
                                f"Cookie {name!r} was observed for context "
                                f"{context.name!r}; missing: {', '.join(missing)}. "
                                "The cookie value was not stored."
                            ),
                            remediation=(
                                "Use HttpOnly for session cookies, set an explicit "
                                "SameSite policy, and use Secure whenever the cookie "
                                "is transported over HTTPS."
                            ),
                            confidence=1.0,
                            cwe="CWE-614",
                        )
                    )

    return observations, findings
