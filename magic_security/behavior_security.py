from __future__ import annotations

import httpx

from magic_security.models import (
    AuthComparison,
    AuthContext,
    CacheObservation,
    CorsImpactObservation,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    RateLimitObservation,
    Severity,
)


_PROBE_ORIGIN = "https://magic-security.invalid"
_RATE_HEADERS = (
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
)


def _protected_urls(comparisons: list[AuthComparison]) -> set[str]:
    return {item.url for item in comparisons if item.boundary == "protected"}


async def verify_protected_cors(
    comparisons: list[AuthComparison],
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
    max_tests: int = 20,
) -> tuple[list[CorsImpactObservation], list[Finding]]:
    observations: list[CorsImpactObservation] = []
    findings: list[Finding] = []

    protected = sorted(_protected_urls(comparisons))[:max_tests]
    if not protected:
        return observations, findings

    for context in contexts:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.7 local-security-scanner",
                "Accept": "application/json,text/html;q=0.8,*/*;q=0.5",
                **context.headers,
            },
            cookies=context.cookies,
        ) as client:
            for url in protected:
                try:
                    response = await client.get(url, headers={"Origin": _PROBE_ORIGIN})
                except httpx.HTTPError:
                    continue

                allow_origin = response.headers.get("access-control-allow-origin", "").strip()
                allow_credentials = (
                    response.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
                )
                reflected = allow_origin == _PROBE_ORIGIN
                readable_policy = reflected and allow_credentials and response.status_code == 200

                observations.append(
                    CorsImpactObservation(
                        url=url,
                        context=context.name,
                        status_code=response.status_code,
                        origin_reflected=reflected,
                        credentials_allowed=allow_credentials,
                        protected_response_exposed=readable_policy,
                    )
                )

                if not readable_policy:
                    continue

                findings.append(
                    Finding(
                        title="Credentialed CORS policy exposes a protected endpoint",
                        severity=Severity.HIGH,
                        kind=FindingKind.EXPOSURE,
                        url=url,
                        description=(
                            "A protected authenticated endpoint reflected an untrusted Origin and enabled credentials."
                        ),
                        evidence=(
                            f"Context {context.name!r} received HTTP 200 while Origin {_PROBE_ORIGIN!r} "
                            "was reflected and Access-Control-Allow-Credentials was true. "
                            "Response body and credential values were not stored."
                        ),
                        remediation=(
                            "Use an explicit trusted-origin allowlist and never reflect arbitrary origins on "
                            "credentialed protected endpoints."
                        ),
                        confidence=1.0,
                        cwe="CWE-942",
                    )
                )

    return observations, findings


async def analyze_authenticated_cache(
    comparisons: list[AuthComparison],
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
    max_tests: int = 20,
) -> tuple[list[CacheObservation], list[Finding]]:
    observations: list[CacheObservation] = []
    findings: list[Finding] = []

    interesting = [
        item for item in comparisons
        if item.boundary == "protected" and item.authenticated_responses_differ
    ][:max_tests]

    for comparison in interesting:
        for context in contexts[:2]:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                headers={
                    "User-Agent": "Magic-Security/0.7 local-security-scanner",
                    **context.headers,
                },
                cookies=context.cookies,
            ) as client:
                try:
                    response = await client.get(comparison.url)
                except httpx.HTTPError:
                    continue

            cache_control = response.headers.get("cache-control", "").lower()
            risky = (
                response.status_code == 200
                and (
                    "public" in cache_control
                    or "s-maxage=" in cache_control
                )
            )

            observations.append(
                CacheObservation(
                    url=comparison.url,
                    context=context.name,
                    cache_control=cache_control,
                    risky_shared_cache=risky,
                )
            )

            if risky:
                findings.append(
                    Finding(
                        title="User-specific authenticated response is marked for shared caching",
                        severity=Severity.HIGH,
                        kind=FindingKind.EXPOSURE,
                        url=comparison.url,
                        description=(
                            "A protected response that differs between users is explicitly cacheable by shared caches."
                        ),
                        evidence=(
                            f"Context {context.name!r} received HTTP 200 with Cache-Control={cache_control!r}. "
                            "The authenticated response body was not stored."
                        ),
                        remediation=(
                            "Use Cache-Control: private or no-store for user-specific authenticated responses "
                            "and review CDN/proxy cache rules."
                        ),
                        confidence=1.0,
                        cwe="CWE-525",
                    )
                )

    return observations, findings


async def classify_rate_limits(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_endpoints: int = 8,
    requests_per_endpoint: int = 6,
) -> list[RateLimitObservation]:
    observations: list[RateLimitObservation] = []

    candidates = [
        endpoint for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    ][:max_endpoints]

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        for endpoint in candidates:
            statuses: list[int] = []
            observed_headers: set[str] = set()

            for _ in range(requests_per_endpoint):
                try:
                    response = await client.get(
                        endpoint.url,
                        headers={"User-Agent": "Magic-Security/0.7 local-security-scanner"},
                    )
                except httpx.HTTPError:
                    break

                statuses.append(response.status_code)
                for header in _RATE_HEADERS:
                    if header in response.headers:
                        observed_headers.add(header)

                if response.status_code == 429:
                    break

            observations.append(
                RateLimitObservation(
                    url=endpoint.url,
                    method=endpoint.method,
                    requests_sent=len(statuses),
                    statuses=tuple(statuses),
                    throttled=429 in statuses,
                    rate_limit_headers=tuple(sorted(observed_headers)),
                )
            )

    return observations
