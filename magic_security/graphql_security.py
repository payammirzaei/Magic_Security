"""GraphQL security probes (introspection + STEP 25 bounded extensions)."""

from __future__ import annotations

from typing import Any

import httpx

from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    FindingKind,
    GraphqlObservation,
    NormalizedEndpoint,
    Severity,
)
from magic_security.transport import SecureTransport


_INTROSPECTION_QUERY = (
    "query MagicSecurityProbe{__schema{queryType{name} mutationType{name}}}"
)
_FIELD_INTROSPECTION = (
    "query MagicSecurityFields{"
    "__schema{queryType{fields{name}} mutationType{fields{name}}}}"
)
_SENSITIVE_FIELD_NAMES = (
    "password",
    "secret",
    "token",
    "ssn",
    "email",
    "phone",
    "creditcard",
    "apikey",
    "private",
)
_MUTATION_DENY = ("delete", "drop", "update", "create", "mutate", "remove")
_DEPTH_CAP = 5
_ALIAS_CAP = 5


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

    async with SecureTransport(follow_redirects=False, timeout=timeout) as client:
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
                            for key in (
                                "exception",
                                "stacktrace",
                                "debug",
                                "trace",
                            )
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
                            "The GraphQL schema can be introspected without "
                            "authentication."
                        ),
                        evidence=(
                            "A minimal introspection query returned __schema "
                            f"metadata with HTTP {response.status_code}."
                        ),
                        remediation=(
                            "Keep introspection public only when intentional. "
                            "Otherwise restrict it in production while "
                            "preserving schema access for trusted tooling."
                        ),
                        confidence=1.0,
                        cwe="CWE-200",
                        check_id="graphql.introspection.anonymous",
                    )
                )

            if detailed_errors:
                findings.append(
                    Finding(
                        title="GraphQL error responses expose debug details",
                        severity=Severity.MEDIUM,
                        kind=FindingKind.EXPOSURE,
                        url=url,
                        description=(
                            "GraphQL error extensions contain debug/exception "
                            "metadata."
                        ),
                        evidence=(
                            "Error extensions included exception, trace, "
                            "stacktrace, or debug fields."
                        ),
                        remediation=(
                            "Return generic production errors and keep server "
                            "exception details in logs."
                        ),
                        confidence=1.0,
                        cwe="CWE-209",
                        check_id="graphql.errors.debug",
                    )
                )

    return observations, findings


def _extract_query_fields(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return []
    schema = (data.get("data") or {}).get("__schema")
    if not isinstance(schema, dict):
        return []
    query_type = schema.get("queryType")
    if not isinstance(query_type, dict):
        return []
    fields = query_type.get("fields")
    if not isinstance(fields, list):
        return []
    names: list[str] = []
    for item in fields[:50]:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


async def probe_graphql_sensitive_fields(
    urls: list[str],
    *,
    auth_contexts: list[AuthContext] | None = None,
    timeout: float = 5.0,
) -> tuple[list[Finding], dict[str, list[str]]]:
    findings: list[Finding] = []
    exercised: list[str] = []
    skipped: list[str] = []

    async with SecureTransport(follow_redirects=False, timeout=timeout) as client:
        for url in urls[:5]:
            try:
                response = await client.post(
                    url,
                    json={"query": _FIELD_INTROSPECTION},
                    headers={
                        "User-Agent": "Magic-Security/1.1 local-security-scanner",
                        "Accept": "application/json",
                    },
                )
                data = response.json()
            except (httpx.HTTPError, ValueError):
                continue

            fields = _extract_query_fields(data)
            sensitive = [
                name
                for name in fields
                if any(token in name.lower() for token in _SENSITIVE_FIELD_NAMES)
                and not any(deny in name.lower() for deny in _MUTATION_DENY)
            ][:5]
            if not sensitive:
                continue

            exercised.append("sensitive_field_probe")
            for field_name in sensitive:
                query = f"query MagicSecurityField {{ {field_name} }}"
                try:
                    anon = await client.post(
                        url,
                        json={"query": query},
                        headers={"Accept": "application/json"},
                    )
                except httpx.HTTPError:
                    continue
                body_len = len(anon.content)
                if anon.status_code == 200 and body_len > 2:
                    findings.append(
                        Finding(
                            title=(
                                "Anonymous GraphQL sensitive-looking field "
                                "resolvable"
                            ),
                            severity=Severity.MEDIUM,
                            kind=FindingKind.EXPOSURE,
                            url=url,
                            description=(
                                "A schema field with a sensitive-looking name "
                                "resolved anonymously via a read-only query."
                            ),
                            evidence=(
                                f"Field name pattern matched; HTTP "
                                f"{anon.status_code}; body_len={body_len}. "
                                "Field values not stored."
                            ),
                            remediation=(
                                "Require auth for sensitive GraphQL fields."
                            ),
                            confidence=0.85,
                            check_id="graphql.field.sensitive.anonymous",
                        )
                    )

            if auth_contexts and len(auth_contexts) >= 2:
                exercised.append("auth_field_comparison")
                first, second = auth_contexts[0], auth_contexts[1]
                field_name = sensitive[0]
                query = f"query MagicSecurityAuthField {{ {field_name} }}"
                try:
                    async with SecureTransport(
                        follow_redirects=False,
                        timeout=timeout,
                        headers=first.headers,
                        cookies=first.cookies,
                    ) as c1:
                        r1 = await c1.post(
                            url,
                            json={"query": query},
                            headers={"Accept": "application/json"},
                        )
                    async with SecureTransport(
                        follow_redirects=False,
                        timeout=timeout,
                        headers=second.headers,
                        cookies=second.cookies,
                    ) as c2:
                        r2 = await c2.post(
                            url,
                            json={"query": query},
                            headers={"Accept": "application/json"},
                        )
                except httpx.HTTPError:
                    continue
                if (
                    r1.status_code == r2.status_code == 200
                    and r1.content
                    and r1.content == r2.content
                    and len(r1.content) > 20
                ):
                    findings.append(
                        Finding(
                            title=(
                                "GraphQL field response identical across "
                                "auth contexts"
                            ),
                            severity=Severity.LOW,
                            kind=FindingKind.EXPOSURE,
                            url=url,
                            description=(
                                "Two auth contexts received identical "
                                "responses for a sensitive-looking field."
                            ),
                            evidence=(
                                f"Contexts {first.name!r} and {second.name!r} "
                                f"same status/body_len={len(r1.content)}. "
                                "Bodies not stored."
                            ),
                            remediation=(
                                "Scope GraphQL resolvers to the authenticated "
                                "principal."
                            ),
                            confidence=0.8,
                            check_id="graphql.field.auth-compare",
                        )
                    )
            else:
                skipped.append("auth_field_comparison")

    if "sensitive_field_probe" not in exercised:
        skipped.append("sensitive_field_probe")

    return findings, {"exercised": exercised, "skipped": skipped}


def build_depth_query(depth: int = _DEPTH_CAP, aliases: int = _ALIAS_CAP) -> str:
    depth = max(1, min(int(depth), _DEPTH_CAP))
    aliases = max(1, min(int(aliases), _ALIAS_CAP))
    inner = "__typename"
    for _ in range(depth - 1):
        inner = "{ __typename " + inner + " }"
    alias_blocks = [f"a{index}: __typename" for index in range(aliases)]
    return (
        "query MagicSecurityDepth { "
        + " ".join(alias_blocks)
        + " nested "
        + inner
        + " }"
    )


async def probe_graphql_depth(
    urls: list[str],
    *,
    timeout: float = 5.0,
) -> tuple[list[Finding], dict[str, list[str]]]:
    findings: list[Finding] = []
    query = build_depth_query(_DEPTH_CAP, _ALIAS_CAP)

    async with SecureTransport(follow_redirects=False, timeout=timeout) as client:
        for url in urls[:5]:
            try:
                response = await client.post(
                    url,
                    json={"query": query},
                    headers={"Accept": "application/json"},
                )
            except httpx.HTTPError:
                continue
            rejected = response.status_code >= 400
            findings.append(
                Finding(
                    title="GraphQL depth/complexity posture observed",
                    severity=Severity.INFO,
                    kind=FindingKind.HARDENING,
                    url=url,
                    description=(
                        "Bounded depth/alias probe executed with hard caps "
                        f"(depth≤{_DEPTH_CAP}, aliases≤{_ALIAS_CAP})."
                    ),
                    evidence=(
                        f"HTTP {response.status_code}; rejected={rejected}; "
                        f"query_len={len(query)}. Body not stored."
                    ),
                    remediation=(
                        "Enforce depth and complexity limits on GraphQL "
                        "executors."
                    ),
                    confidence=0.7,
                    check_id="graphql.depth.observation",
                )
            )
    return findings, {"exercised": ["depth_complexity"]}


async def probe_graphql_subscriptions(
    crawl: CrawlResult,
    urls: list[str],
) -> tuple[list[Finding], dict[str, list[str]]]:
    findings: list[Finding] = []
    discovered: set[str] = set()
    for analysis in crawl.js_analysis:
        for path in analysis.get("graphql_paths") or []:
            text = str(path)
            if "subscription" in text.lower() or text.endswith("/graphql"):
                discovered.add(text)
    for url in urls:
        if "subscription" in url.lower():
            discovered.add(url)
        if url.rstrip("/").endswith("/graphql"):
            discovered.add(url.rstrip("/") + "/subscriptions")

    for url in sorted(discovered)[:10]:
        findings.append(
            Finding(
                title="GraphQL subscription endpoint candidate discovered",
                severity=Severity.INFO,
                kind=FindingKind.HARDENING,
                url=url,
                description=(
                    "A subscription-related GraphQL path was discovered from "
                    "schema/JS hints (no message flood performed)."
                ),
                evidence="Path heuristic / JS analysis hint only.",
                remediation=(
                    "Authenticate subscription channels and validate origin."
                ),
                confidence=0.55,
                check_id="graphql.subscription.discovery",
            )
        )
    return findings, {"exercised": ["subscription_discovery"]}
