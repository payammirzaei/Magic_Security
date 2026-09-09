from __future__ import annotations

from typing import Any

import httpx

from magic_security.transport import open_secure_transport

from magic_security.models import (
    EndpointObservation,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    Severity,
)


_SENSITIVE_PERSONAL_KEYS = {
    "email",
    "email_address",
    "phone",
    "phone_number",
    "mobile",
    "address",
    "street",
    "postal_code",
    "postcode",
    "date_of_birth",
    "dob",
    "birth_date",
    "iban",
    "bank_account",
}

_SECRET_KEYS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "session_token",
    "jwt",
}


def _walk_json_keys(value: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()

    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            paths.add(path)
            paths.update(_walk_json_keys(child, path))
    elif isinstance(value, list):
        for child in value[:20]:
            paths.update(_walk_json_keys(child, prefix))

    return paths


def _classify_status(status: int, content_type: str, body: bytes) -> str:
    if status in {401, 403}:
        return "auth_required"
    if status in {301, 302, 303, 307, 308}:
        return "redirect"
    if status == 404:
        return "not_found"
    if status >= 500:
        return "server_error"
    if status >= 400:
        return "client_error"
    if not body:
        return "empty"
    if "json" in content_type:
        return "json"
    if "html" in content_type:
        return "html"
    return "other"


def _field_matches(paths: set[str], names: set[str]) -> tuple[str, ...]:
    matched = {
        path
        for path in paths
        if path.rsplit(".", 1)[-1].lower() in names
    }
    return tuple(sorted(matched))


async def classify_endpoints(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_endpoints: int = 50,
) -> tuple[list[EndpointObservation], list[Finding]]:
    observations: list[EndpointObservation] = []
    findings: list[Finding] = []

    candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    ][:max_endpoints]

    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.5 local-security-scanner",
            "Accept": "application/json,text/html;q=0.8,*/*;q=0.5",
        },
    ) as client:
        for endpoint in candidates:
            try:
                response = await client.get(endpoint.url)
            except httpx.HTTPError:
                continue

            content_type = response.headers.get("content-type", "").lower()
            body = response.content[:500_000]
            classification = _classify_status(
                response.status_code,
                content_type,
                body,
            )

            sensitive_fields: tuple[str, ...] = ()
            secret_fields: tuple[str, ...] = ()

            if response.status_code == 200 and "json" in content_type:
                try:
                    data = response.json()
                except ValueError:
                    data = None

                if data is not None:
                    paths = _walk_json_keys(data)
                    sensitive_fields = _field_matches(
                        paths,
                        _SENSITIVE_PERSONAL_KEYS,
                    )
                    secret_fields = _field_matches(paths, _SECRET_KEYS)

            observations.append(
                EndpointObservation(
                    url=endpoint.url,
                    method=endpoint.method,
                    status_code=response.status_code,
                    classification=classification,
                    content_type=content_type.split(";", 1)[0].strip(),
                    sensitive_fields=sensitive_fields,
                    secret_fields=secret_fields,
                )
            )

            exposed_fields = tuple(
                sorted(set(sensitive_fields) | set(secret_fields))
            )
            if not exposed_fields:
                continue

            leaf_names = tuple(
                sorted({path.rsplit(".", 1)[-1] for path in exposed_fields})
            )
            field_signature = ", ".join(leaf_names)

            if secret_fields:
                severity = Severity.HIGH
                title = "Unauthenticated JSON exposes secret-like fields"
            else:
                severity = Severity.MEDIUM
                title = "Unauthenticated JSON exposes sensitive-looking fields"

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    kind=FindingKind.EXPOSURE,
                    url=endpoint.url,
                    description=(
                        "A GET request with no authentication or session cookies "
                        "returned HTTP 200 JSON containing these security-relevant "
                        f"field names: {field_signature}."
                    ),
                    evidence=(
                        "Unauthenticated HTTP 200 JSON contained field paths: "
                        + ", ".join(exposed_fields[:20])
                        + ". Values were intentionally not stored."
                    ),
                    remediation=(
                        "Confirm the data is intended to be public. If not, require "
                        "authentication and enforce object/field-level authorization."
                    ),
                    confidence=1.0,
                    owasp="A01:2025 Broken Access Control",
                    cwe="CWE-200",
                )
            )

    return observations, findings
