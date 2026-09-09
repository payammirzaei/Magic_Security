from __future__ import annotations

import json
import re
from itertools import combinations
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx

from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.transport import open_secure_transport

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
    "uuid",
    "uid",
    "token",
}

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_\-]{16,128}$")
_NUMERIC_RE = re.compile(r"^\d{1,18}$")


def _collect_identifiers(
    value: Any,
    found: dict[str, set[str]],
    *,
    depth: int = 0,
) -> None:
    if depth > 6:
        return
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
            _collect_identifiers(child, found, depth=depth + 1)
    elif isinstance(value, list):
        for child in value[:20]:
            _collect_identifiers(child, found, depth=depth + 1)


def _looks_opaque_id(value: str) -> bool:
    if _UUID_RE.fullmatch(value):
        return True
    if _NUMERIC_RE.fullmatch(value):
        return True
    if _OPAQUE_RE.fullmatch(value) and not value.isalpha():
        return True
    return False


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


def _semantic_fingerprint(response: httpx.Response) -> str | None:
    try:
        data = response.json()
    except ValueError:
        content_type = response.headers.get("content-type", "").split(";", 1)[0]
        return (
            f"{response.status_code}|{content_type.lower()}|"
            f"{len(response.content)}"
        )

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _json_fingerprint(response: httpx.Response) -> str | None:
    return _semantic_fingerprint(response)


def _ownership_confidence(
    *,
    owner_reread_match: bool,
    public_match: bool,
    semantic_match: bool,
) -> float:
    if public_match or not semantic_match:
        return 0.0
    score = 0.7
    if owner_reread_match:
        score += 0.25
    return min(score, 1.0)


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

    async with open_secure_transport(
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
        value = next(iter(direct))
        if _looks_opaque_id(value) or True:
            return value

    for name, values in identifiers.items():
        if name.endswith(key) or key.endswith(name):
            if len(values) == 1:
                return next(iter(values))

    return None


def _candidate_specs(
    endpoints: list[NormalizedEndpoint],
) -> list[tuple[NormalizedEndpoint, str, str]]:
    specs: list[tuple[NormalizedEndpoint, str, str]] = []

    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue

        path_params = _template_parameters(endpoint.url)
        id_path_params = [
            name for name in path_params if _is_identifier_name(name)
        ]
        # Nested path IDs: exercise each identifier parameter when all
        # path params look like IDs (e.g. /orgs/{org_id}/users/{user_id}).
        if id_path_params and len(id_path_params) == len(path_params):
            for name in id_path_params:
                specs.append((endpoint, name, "path"))
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
    *,
    extra_path_values: dict[str, str] | None = None,
) -> str:
    if location == "path":
        url = endpoint.url
        if extra_path_values:
            for name, raw in extra_path_values.items():
                url = _substitute_path(url, name, raw)
        return _substitute_path(url, parameter, value)
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
        open_secure_transport(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.8 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
                **owner.headers,
            },
            cookies=owner.cookies,
        ) as owner_client,
        open_secure_transport(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.8 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
                **requester.headers,
            },
            cookies=requester.cookies,
        ) as requester_client,
        open_secure_transport(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.8 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
            },
        ) as anon_client,
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

            extra: dict[str, str] = {}
            if location == "path":
                for sibling in _template_parameters(endpoint.url):
                    if sibling == parameter:
                        continue
                    sibling_id = _owned_id_for_parameter(owner_ids, sibling)
                    if sibling_id:
                        extra[sibling] = sibling_id

            tested += 1
            owner_url = _build_url(
                endpoint,
                parameter,
                location,
                owner_id,
                extra_path_values=extra or None,
            )

            try:
                owner_response = await owner_client.get(owner_url)
                owner_reread = await owner_client.get(
                    owner_url,
                    headers={
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache",
                    },
                )
                cross_response = await requester_client.get(
                    owner_url,
                    headers={"Cache-Control": "no-cache"},
                )
            except httpx.HTTPError:
                continue

            try:
                public_response = await anon_client.get(owner_url)
            except httpx.HTTPError:
                public_response = None

            owner_fp = _semantic_fingerprint(owner_response)
            reread_fp = _semantic_fingerprint(owner_reread)
            cross_fp = _semantic_fingerprint(cross_response)
            public_fp = (
                _semantic_fingerprint(public_response)
                if public_response is not None
                else None
            )

            owner_reread_match = (
                owner_response.status_code == 200
                and owner_reread.status_code == 200
                and owner_fp is not None
                and owner_fp == reread_fp
            )
            public_match = (
                public_response is not None
                and public_response.status_code == 200
                and public_fp is not None
                and public_fp == owner_fp
            )
            generic_empty = cross_response.status_code in {401, 403} or (
                cross_response.status_code == 200
                and len(cross_response.content) <= 2
            )
            semantic_match = (
                owner_response.status_code == 200
                and cross_response.status_code == 200
                and owner_fp is not None
                and cross_fp == owner_fp
                and not generic_empty
            )
            confidence = _ownership_confidence(
                owner_reread_match=owner_reread_match,
                public_match=public_match,
                semantic_match=semantic_match,
            )
            verified = (
                confidence >= 0.95
                and semantic_match
                and not public_match
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

            finding = Finding(
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
                    f"{parameter!r}. Owner and cross-account semantic "
                    "fingerprints matched after negative controls "
                    f"(ownership_confidence={confidence:.2f}). "
                    "Raw bodies, PII, and object identifiers were not stored."
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
                check_id="authorization.bola.read",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="authorization.bola.read",
                    proof_type="pairwise_cross_account_read",
                    baseline_summary=(
                        f"Owner {owner.name} read own object "
                        f"(status={owner_response.status_code}, "
                        f"len={len(owner_response.content)})"
                    ),
                    mutation_summary=(
                        f"Requester {requester.name} read owner object "
                        "with cache-bust; public/anonymous control compared"
                    ),
                    observed_result=(
                        f"semantic_match=true; public_match=false; "
                        f"owner_reread_match={owner_reread_match}; "
                        f"ownership_confidence={confidence:.2f}"
                    ),
                    redacted_artifacts={
                        "owner_status": owner_response.status_code,
                        "requester_status": cross_response.status_code,
                        "owner_len": len(owner_response.content),
                        "requester_len": len(cross_response.content),
                        "ownership_confidence": confidence,
                    },
                    confidence="verified",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)

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
