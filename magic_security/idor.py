from __future__ import annotations

import json
from itertools import combinations
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx

from magic_security.models import (
    AuthComparison,
    AuthContext,
    Finding,
    FindingKind,
    IdorObservation,
    NormalizedEndpoint,
    OwnershipObservation,
    PairwiseIdorObservation,
    Severity,
)


_ID_NAMES = {
    "id",
    "user_id",
    "account_id",
    "customer_id",
    "profile_id",
    "order_id",
    "invoice_id",
    "project_id",
    "organization_id",
    "org_id",
}


def _collect_identifiers(
    value: Any,
    found: dict[str, set[str]],
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key).lower()
            if (
                key_text in _ID_NAMES
                or key_text.endswith("_id")
            ) and isinstance(child, (str, int)):
                text = str(child)
                if text and len(text) <= 128:
                    found.setdefault(key_text, set()).add(text)
            _collect_identifiers(child, found)
    elif isinstance(value, list):
        for child in value[:20]:
            _collect_identifiers(child, found)


def _template_parameters(url: str) -> tuple[str, ...]:
    params: list[str] = []
    cursor = 0

    while True:
        left = url.find("{", cursor)
        if left < 0:
            break
        right = url.find("}", left + 1)
        if right < 0:
            break
        name = url[left + 1:right].strip()
        if name:
            params.append(name)
        cursor = right + 1

    return tuple(params)


def _is_identifier_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in _ID_NAMES or lowered.endswith("_id")


def _substitute_path(url: str, parameter: str, value: str) -> str:
    return url.replace(
        "{" + parameter + "}",
        quote(value, safe=""),
        1,
    )


def _set_query_parameter(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query = [(key, current) for key, current in query if key != parameter]
    query.append((parameter, value))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(query, doseq=True),
            parts.fragment,
        )
    )


def _json_fingerprint(response: httpx.Response) -> str | None:
    try:
        data = response.json()
    except ValueError:
        return None

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _preferred_ownership_urls(
    auth_comparisons: list[AuthComparison] | None,
) -> set[str]:
    if not auth_comparisons:
        return set()

    user_specific = {
        item.url
        for item in auth_comparisons
        if item.boundary == "protected"
        and item.authenticated_responses_differ
    }
    if user_specific:
        return user_specific

    return {
        item.url
        for item in auth_comparisons
        if item.boundary == "protected"
    }


async def _discover_owned_ids(
    endpoints: list[NormalizedEndpoint],
    context: AuthContext,
    *,
    timeout: float,
    max_endpoints: int,
    preferred_urls: set[str] | None = None,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    found: dict[str, set[str]] = {}
    sources: dict[str, set[str]] = {}

    candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    ]

    if preferred_urls:
        preferred = [
            endpoint
            for endpoint in candidates
            if endpoint.url in preferred_urls
        ]
        if preferred:
            candidates = preferred

    candidates = candidates[:max_endpoints]

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.8 local-security-scanner",
            "Accept": "application/json,*/*;q=0.5",
            **context.headers,
        },
        cookies=context.cookies,
    ) as client:
        for endpoint in candidates:
            try:
                response = await client.get(endpoint.url)
            except httpx.HTTPError:
                continue

            if response.status_code != 200:
                continue
            if "json" not in response.headers.get("content-type", "").lower():
                continue

            try:
                data = response.json()
            except ValueError:
                continue

            before = {
                key: set(values)
                for key, values in found.items()
            }
            _collect_identifiers(data, found)

            for key, values in found.items():
                if values != before.get(key, set()):
                    sources.setdefault(key, set()).add(endpoint.url)

    return found, sources


def _owned_id_for_parameter(
    identifiers: dict[str, set[str]],
    parameter: str,
) -> str | None:
    key = parameter.lower()
    direct = identifiers.get(key)

    if direct and len(direct) == 1:
        return next(iter(direct))

    return None


def _candidate_specs(
    endpoints: list[NormalizedEndpoint],
) -> list[tuple[NormalizedEndpoint, str, str]]:
    specs: list[tuple[NormalizedEndpoint, str, str]] = []

    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue

        path_params = _template_parameters(endpoint.url)
        if len(path_params) == 1 and _is_identifier_name(path_params[0]):
            specs.append((endpoint, path_params[0], "path"))
            continue

        if path_params:
            continue

        for parameter in endpoint.parameters:
            if _is_identifier_name(parameter):
                specs.append((endpoint, parameter, "query"))

    return specs


def _build_url(
    endpoint: NormalizedEndpoint,
    parameter: str,
    location: str,
    value: str,
) -> str:
    if location == "path":
        return _substitute_path(endpoint.url, parameter, value)
    return _set_query_parameter(endpoint.url, parameter, value)


async def _verify_pair(
    endpoints: list[NormalizedEndpoint],
    owner: AuthContext,
    requester: AuthContext,
    *,
    timeout: float,
    max_discovery_endpoints: int,
    max_candidates: int,
    preferred_urls: set[str],
) -> tuple[
    list[OwnershipObservation],
    list[PairwiseIdorObservation],
    list[Finding],
]:
    owner_ids, owner_sources = await _discover_owned_ids(
        endpoints,
        owner,
        timeout=timeout,
        max_endpoints=max_discovery_endpoints,
        preferred_urls=preferred_urls,
    )
    requester_ids, requester_sources = await _discover_owned_ids(
        endpoints,
        requester,
        timeout=timeout,
        max_endpoints=max_discovery_endpoints,
        preferred_urls=preferred_urls,
    )

    ownership: list[OwnershipObservation] = []
    for context, identifiers, sources in (
        (owner, owner_ids, owner_sources),
        (requester, requester_ids, requester_sources),
    ):
        for parameter, values in sorted(identifiers.items()):
            ownership.append(
                OwnershipObservation(
                    context=context.name,
                    parameter=parameter,
                    discovered_values=len(values),
                    source_endpoints=tuple(
                        sorted(sources.get(parameter, set()))
                    ),
                )
            )

    observations: list[PairwiseIdorObservation] = []
    findings: list[Finding] = []
    tested = 0

    async with (
        httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.8 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
                **owner.headers,
            },
            cookies=owner.cookies,
        ) as owner_client,
        httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.8 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
                **requester.headers,
            },
            cookies=requester.cookies,
        ) as requester_client,
    ):
        for endpoint, parameter, location in _candidate_specs(endpoints):
            if tested >= max_candidates:
                break

            owner_id = _owned_id_for_parameter(owner_ids, parameter)
            requester_id = _owned_id_for_parameter(
                requester_ids,
                parameter,
            )

            if (
                not owner_id
                or not requester_id
                or owner_id == requester_id
            ):
                continue

            tested += 1
            owner_url = _build_url(
                endpoint,
                parameter,
                location,
                owner_id,
            )

            try:
                owner_response = await owner_client.get(owner_url)
                cross_response = await requester_client.get(owner_url)
            except httpx.HTTPError:
                continue

            owner_fp = _json_fingerprint(owner_response)
            cross_fp = _json_fingerprint(cross_response)

            verified = (
                owner_response.status_code == 200
                and cross_response.status_code == 200
                and owner_fp is not None
                and cross_fp == owner_fp
            )

            observations.append(
                PairwiseIdorObservation(
                    endpoint=endpoint.url,
                    parameter=parameter,
                    parameter_location=location,
                    owner_context=owner.name,
                    requester_context=requester.name,
                    owner_status=owner_response.status_code,
                    requester_status=cross_response.status_code,
                    cross_account_verified=verified,
                )
            )

            if not verified:
                continue

            findings.append(
                Finding(
                    title=(
                        f"Cross-account object access verified "
                        f"({location})"
                    ),
                    severity=Severity.HIGH,
                    kind=FindingKind.VULNERABILITY,
                    url=endpoint.url,
                    description=(
                        "Authenticated same-role test contexts verified "
                        "cross-account read access through "
                        f"{location} parameter {parameter!r}."
                    ),
                    evidence=(
                        f"{requester.name!r} retrieved an object belonging "
                        f"to {owner.name!r} through a {location} parameter "
                        f"{parameter!r}. Owner and cross-account responses "
                        "were HTTP 200 and identical JSON. Credentials and "
                        "raw object identifiers were not stored."
                    ),
                    remediation=(
                        "Enforce object-level authorization for every "
                        "request. Resolve requested resources through the "
                        "authenticated principal's allowed scope rather "
                        "than trusting client IDs."
                    ),
                    confidence=1.0,
                    owasp="A01:2025 Broken Access Control",
                    cwe="CWE-639",
                )
            )

    return ownership, observations, findings


async def verify_pairwise_idor_read_access(
    endpoints: list[NormalizedEndpoint],
    contexts: list[AuthContext],
    *,
    auth_comparisons: list[AuthComparison] | None = None,
    timeout: float = 5.0,
    max_discovery_endpoints: int = 40,
    max_candidates_per_pair: int = 20,
) -> tuple[
    list[OwnershipObservation],
    list[PairwiseIdorObservation],
    list[Finding],
]:
    if len(contexts) < 2:
        return [], [], []

    preferred_urls = _preferred_ownership_urls(auth_comparisons)
    ownership_index: dict[
        tuple[str, str],
        OwnershipObservation,
    ] = {}
    observations: list[PairwiseIdorObservation] = []
    findings: list[Finding] = []

    for first, second in combinations(contexts, 2):
        if (
            first.role
            and second.role
            and first.role != second.role
        ):
            continue

        for owner, requester in (
            (first, second),
            (second, first),
        ):
            (
                pair_ownership,
                pair_observations,
                pair_findings,
            ) = await _verify_pair(
                endpoints,
                owner,
                requester,
                timeout=timeout,
                max_discovery_endpoints=max_discovery_endpoints,
                max_candidates=max_candidates_per_pair,
                preferred_urls=preferred_urls,
            )

            for item in pair_ownership:
                key = (item.context, item.parameter)
                current = ownership_index.get(key)

                if current is None:
                    ownership_index[key] = item
                    continue

                ownership_index[key] = OwnershipObservation(
                    context=item.context,
                    parameter=item.parameter,
                    discovered_values=max(
                        current.discovered_values,
                        item.discovered_values,
                    ),
                    source_endpoints=tuple(
                        sorted(
                            set(current.source_endpoints)
                            | set(item.source_endpoints)
                        )
                    ),
                )

            observations.extend(pair_observations)
            findings.extend(pair_findings)

    unique_observations: dict[
        tuple[str, str, str, str, str],
        PairwiseIdorObservation,
    ] = {}

    for item in observations:
        key = (
            item.endpoint,
            item.parameter,
            item.parameter_location,
            item.owner_context,
            item.requester_context,
        )
        unique_observations[key] = item

    return (
        sorted(
            ownership_index.values(),
            key=lambda item: (
                item.context,
                item.parameter,
            ),
        ),
        sorted(
            unique_observations.values(),
            key=lambda item: (
                item.endpoint,
                item.parameter,
                item.owner_context,
                item.requester_context,
            ),
        ),
        findings,
    )


async def verify_idor_read_access(
    endpoints: list[NormalizedEndpoint],
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
    max_discovery_endpoints: int = 40,
    max_templates: int = 20,
) -> tuple[list[IdorObservation], list[Finding]]:
    """Backward-compatible two-context wrapper."""

    if len(contexts) < 2:
        return [], []

    _, pairwise, findings = await verify_pairwise_idor_read_access(
        endpoints,
        contexts[:2],
        timeout=timeout,
        max_discovery_endpoints=max_discovery_endpoints,
        max_candidates_per_pair=max_templates,
    )

    first = contexts[0].name
    second = contexts[1].name
    grouped: dict[
        tuple[str, str, str],
        dict[str, PairwiseIdorObservation],
    ] = {}

    for item in pairwise:
        key = (
            item.endpoint,
            item.parameter,
            item.parameter_location,
        )
        grouped.setdefault(key, {})[
            f"{item.owner_context}->{item.requester_context}"
        ] = item

    legacy: list[IdorObservation] = []

    for (
        endpoint,
        parameter,
        location,
    ), directions in grouped.items():
        owner_a_request_b = directions.get(
            f"{first}->{second}"
        )
        owner_b_request_a = directions.get(
            f"{second}->{first}"
        )

        if not owner_a_request_b and not owner_b_request_a:
            continue

        legacy.append(
            IdorObservation(
                endpoint_template=endpoint,
                parameter=parameter,
                user_a_own_status=(
                    owner_a_request_b.owner_status
                    if owner_a_request_b
                    else 0
                ),
                user_b_own_status=(
                    owner_b_request_a.owner_status
                    if owner_b_request_a
                    else 0
                ),
                user_b_to_a_status=(
                    owner_a_request_b.requester_status
                    if owner_a_request_b
                    else 0
                ),
                user_a_to_b_status=(
                    owner_b_request_a.requester_status
                    if owner_b_request_a
                    else 0
                ),
                cross_account_verified=any(
                    item.cross_account_verified
                    for item in (
                        owner_a_request_b,
                        owner_b_request_a,
                    )
                    if item is not None
                ),
                parameter_location=location,
            )
        )

    return legacy, findings
