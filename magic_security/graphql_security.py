from __future__ import annotations

import httpx

from magic_security.models import Finding, FindingKind, GraphqlObservation, NormalizedEndpoint, Severity


_INTROSPECTION_QUERY = "query MagicSecurityProbe{__schema{queryType{name} mutationType{name}}}"


def _graphql_urls(endpoints: list[NormalizedEndpoint]) -> list[str]:
    return sorted(
        {
            endpoint.url
            for endpoint in endpoints
            if "graphql" in endpoint.url.lower()
            and "{" not in endpoint.url
            and "}" not in endpoint.url
        }
    )


async def analyze_graphql(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_endpoints: int = 10,
) -> tuple[list[GraphqlObservation], list[Finding]]:
    observations: list[GraphqlObservation] = []
    findings: list[Finding] = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        for url in _graphql_urls(endpoints)[:max_endpoints]:
            try:
                response = await client.post(
                    url,
                    json={"query": _INTROSPECTION_QUERY},
                    headers={
                        "User-Agent": "Magic-Security/0.7 local-security-scanner",
                        "Accept": "application/json",
                    },
                )
            except httpx.HTTPError:
                continue

            introspection = False
            detailed_errors = False
            try:
                data = response.json()
            except ValueError:
                data = None

            if isinstance(data, dict):
                schema = data.get("data")
                introspection = (
                    isinstance(schema, dict)
                    and isinstance(schema.get("__schema"), dict)
                )

                errors = data.get("errors")
                if isinstance(errors, list):
                    for error in errors:
                        if not isinstance(error, dict):
                            continue
                        extensions = error.get("extensions")
                        if isinstance(extensions, dict) and any(
                            key in extensions
                            for key in ("exception", "stacktrace", "debug", "trace")
                        ):
                            detailed_errors = True

            observations.append(
                GraphqlObservation(
                    url=url,
                    status_code=response.status_code,
                    anonymous_introspection=introspection,
                    detailed_errors=detailed_errors,
                )
            )

            if introspection:
                findings.append(
                    Finding(
                        title="Anonymous GraphQL introspection is enabled",
                        severity=Severity.INFO,
                        kind=FindingKind.EXPOSURE,
                        url=url,
                        description=(
                            "The GraphQL schema can be introspected without authentication."
                        ),
                        evidence=(
                            "A minimal introspection query returned __schema metadata with HTTP "
                            f"{response.status_code}."
                        ),
                        remediation=(
                            "Keep introspection public only when intentional. Otherwise restrict it "
                            "in production while preserving schema access for trusted tooling."
                        ),
                        confidence=1.0,
                        cwe="CWE-200",
                    )
                )

            if detailed_errors:
                findings.append(
                    Finding(
                        title="GraphQL error responses expose debug details",
                        severity=Severity.MEDIUM,
                        kind=FindingKind.EXPOSURE,
                        url=url,
                        description="GraphQL error extensions contain debug/exception metadata.",
                        evidence="Error extensions included exception, trace, stacktrace, or debug fields.",
                        remediation="Return generic production errors and keep server exception details in logs.",
                        confidence=1.0,
                        cwe="CWE-209",
                    )
                )

    return observations, findings
