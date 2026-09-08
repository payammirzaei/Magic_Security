from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import httpx

from magic_security.models import (
    AuthContext,
    Finding,
    FindingKind,
    IdorObservation,
    NormalizedEndpoint,
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


def _collect_identifiers(value: Any, found: dict[str, set[str]]) -> None:
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


def _substitute(url: str, parameter: str, value: str) -> str:
    return url.replace(
        "{" + parameter + "}",
        quote(value, safe=""),
        1,
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


async def _discover_owned_ids(
    endpoints: list[NormalizedEndpoint],
    context: AuthContext,
    *,
    timeout: float,
    max_endpoints: int,
) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}

    candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    ][:max_endpoints]

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.7 local-security-scanner",
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

            _collect_identifiers(data, found)

    return found


def _owned_id_for_parameter(
    identifiers: dict[str, set[str]],
    parameter: str,
) -> str | None:
    key = parameter.lower()
    direct = identifiers.get(key)

    if direct and len(direct) == 1:
        return next(iter(direct))

    return None


async def verify_idor_read_access(
    endpoints: list[NormalizedEndpoint],
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
    max_discovery_endpoints: int = 40,
    max_templates: int = 20,
) -> tuple[list[IdorObservation], list[Finding]]:
    """Verify cross-account object reads with explicit test accounts.

    Only GET requests are issued. No brute forcing occurs: object identifiers
    must first be observed in each user's own authenticated JSON responses.
    """

    if len(contexts) < 2:
        return [], []

    user_a = contexts[0]
    user_b = contexts[1]

    ids_a = await _discover_owned_ids(
        endpoints,
        user_a,
        timeout=timeout,
        max_endpoints=max_discovery_endpoints,
    )
    ids_b = await _discover_owned_ids(
        endpoints,
        user_b,
        timeout=timeout,
        max_endpoints=max_discovery_endpoints,
    )

    templates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" in endpoint.url
        and "}" in endpoint.url
    ]

    observations: list[IdorObservation] = []
    findings: list[Finding] = []
    tested = 0

    async with (
        httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.7 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
                **user_a.headers,
            },
            cookies=user_a.cookies,
        ) as client_a,
        httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.7 local-security-scanner",
                "Accept": "application/json,*/*;q=0.5",
                **user_b.headers,
            },
            cookies=user_b.cookies,
        ) as client_b,
    ):
        for endpoint in templates:
            if tested >= max_templates:
                break

            params = _template_parameters(endpoint.url)
            if len(params) != 1:
                continue

            parameter = params[0]
            own_a = _owned_id_for_parameter(ids_a, parameter)
            own_b = _owned_id_for_parameter(ids_b, parameter)

            if not own_a or not own_b or own_a == own_b:
                continue

            tested += 1

            url_a = _substitute(endpoint.url, parameter, own_a)
            url_b = _substitute(endpoint.url, parameter, own_b)

            try:
                owner_a = await client_a.get(url_a)
                owner_b = await client_b.get(url_b)
                b_to_a = await client_b.get(url_a)
                a_to_b = await client_a.get(url_b)
            except httpx.HTTPError:
                continue

            owner_a_fp = _json_fingerprint(owner_a)
            owner_b_fp = _json_fingerprint(owner_b)
            b_to_a_fp = _json_fingerprint(b_to_a)
            a_to_b_fp = _json_fingerprint(a_to_b)

            b_reads_a = (
                owner_a.status_code == 200
                and b_to_a.status_code == 200
                and owner_a_fp is not None
                and b_to_a_fp == owner_a_fp
            )
            a_reads_b = (
                owner_b.status_code == 200
                and a_to_b.status_code == 200
                and owner_b_fp is not None
                and a_to_b_fp == owner_b_fp
            )

            verified = b_reads_a or a_reads_b

            observations.append(
                IdorObservation(
                    endpoint_template=endpoint.url,
                    parameter=parameter,
                    user_a_own_status=owner_a.status_code,
                    user_b_own_status=owner_b.status_code,
                    user_b_to_a_status=b_to_a.status_code,
                    user_a_to_b_status=a_to_b.status_code,
                    cross_account_verified=verified,
                )
            )

            if not verified:
                continue

            directions: list[str] = []
            if b_reads_a:
                directions.append("User B retrieved User A's object")
            if a_reads_b:
                directions.append("User A retrieved User B's object")

            findings.append(
                Finding(
                    title=(
                        f"Cross-account object access verified ({location})"
                    ),
                    severity=Severity.HIGH,
                    kind=FindingKind.VULNERABILITY,
                    url=endpoint.url,
                    description=(
                        "Two authenticated test accounts verified cross-account "
                        "read access on an object endpoint."
                    ),
                    evidence=(
                        f"Path parameter {parameter!r}: "
                        + "; ".join(directions)
                        + ". The cross-account HTTP 200 JSON matched the owner's "
                        "baseline response for that object. Credentials and raw "
                        "object identifiers were not stored."
                    ),
                    remediation=(
                        "Enforce object-level authorization for every request. "
                        "Resolve requested resources through the authenticated "
                        "principal's allowed scope instead of trusting path IDs."
                    ),
                    confidence=1.0,
                    owasp="A01:2025 Broken Access Control",
                    cwe="CWE-639",
                )
            )

    return observations, findings
