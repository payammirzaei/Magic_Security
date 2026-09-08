from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx

from magic_security.models import AuthComparison, AuthContext, NormalizedEndpoint


class AuthConfigError(ValueError):
    pass


def load_auth_contexts(path: str | Path) -> list[AuthContext]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthConfigError(
            f"Could not read auth context file: {source}"
        ) from exc

    raw_contexts = data.get("contexts") if isinstance(data, dict) else None
    if not isinstance(raw_contexts, list) or len(raw_contexts) < 2:
        raise AuthConfigError(
            "Auth context file must contain at least two contexts."
        )

    contexts: list[AuthContext] = []
    seen_names: set[str] = set()

    for item in raw_contexts:
        if not isinstance(item, dict):
            raise AuthConfigError("Each auth context must be an object.")

        name = str(item.get("name") or "").strip()
        if not name:
            raise AuthConfigError(
                "Each auth context needs a non-empty name."
            )
        if name.lower() == "anonymous":
            raise AuthConfigError(
                "'anonymous' is reserved by the scanner."
            )
        if name in seen_names:
            raise AuthConfigError(
                f"Duplicate auth context name: {name}"
            )
        seen_names.add(name)

        headers = item.get("headers") or {}
        cookies = item.get("cookies") or {}
        role = item.get("role")

        if not isinstance(headers, dict) or not isinstance(cookies, dict):
            raise AuthConfigError(
                "headers and cookies must be JSON objects."
            )
        if role is not None and not isinstance(role, str):
            raise AuthConfigError(
                "role must be a string when provided."
            )

        contexts.append(
            AuthContext(
                name=name,
                headers={
                    str(key): str(value)
                    for key, value in headers.items()
                },
                cookies={
                    str(key): str(value)
                    for key, value in cookies.items()
                },
                role=(
                    role.strip()
                    if isinstance(role, str) and role.strip()
                    else None
                ),
            )
        )

    return contexts


def _body_fingerprint(response: httpx.Response) -> str:
    body = response.content[:500_000]
    content_type = (
        response.headers.get("content-type", "").split(";", 1)[0]
    )
    payload = (
        f"{response.status_code}\n{content_type.lower()}\n".encode("utf-8")
        + body
    )
    return hashlib.sha256(payload).hexdigest()[:16]


def _response_class(status_code: int) -> str:
    if status_code in {401, 403}:
        return "denied"
    if 200 <= status_code < 300:
        return "allowed"
    if status_code in {301, 302, 303, 307, 308}:
        return "redirect"
    if status_code == 404:
        return "not_found"
    if status_code >= 500:
        return "server_error"
    return "other"


async def map_auth_boundaries(
    endpoints: list[NormalizedEndpoint],
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
    max_endpoints: int = 40,
) -> list[AuthComparison]:
    candidates = [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
    ][:max_endpoints]

    comparisons: list[AuthComparison] = []

    for endpoint in candidates:
        results: dict[str, dict[str, Any]] = {}

        async def execute(
            name: str,
            headers: dict[str, str] | None = None,
            cookies: dict[str, str] | None = None,
        ) -> None:
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=timeout,
                headers={
                    "User-Agent": (
                        "Magic-Security/0.8 local-security-scanner"
                    ),
                    "Accept": (
                        "application/json,text/html;q=0.8,*/*;q=0.5"
                    ),
                    **(headers or {}),
                },
                cookies=cookies or {},
            ) as client:
                try:
                    response = await client.get(endpoint.url)
                except httpx.HTTPError:
                    return

            results[name] = {
                "status_code": response.status_code,
                "access": _response_class(response.status_code),
                "fingerprint": _body_fingerprint(response),
            }

        await execute("anonymous")

        for context in contexts:
            await execute(
                context.name,
                headers=context.headers,
                cookies=context.cookies,
            )

        if not results:
            continue

        anonymous = results.get("anonymous")
        authenticated = {
            name: result
            for name, result in results.items()
            if name != "anonymous"
        }

        boundary = "unknown"

        if anonymous and anonymous["access"] == "denied":
            if any(
                result["access"] == "allowed"
                for result in authenticated.values()
            ):
                boundary = "protected"
            else:
                boundary = "denied_for_all"

        elif anonymous and anonymous["access"] == "allowed":
            if all(
                result["access"] == "allowed"
                for result in authenticated.values()
            ):
                boundary = "public_or_unprotected"
            else:
                boundary = "inconsistent"

        elif authenticated:
            boundary = "inconsistent"

        auth_fingerprints = {
            result["fingerprint"]
            for result in authenticated.values()
            if result["access"] == "allowed"
        }

        comparisons.append(
            AuthComparison(
                url=endpoint.url,
                method=endpoint.method,
                boundary=boundary,
                anonymous_status=(
                    anonymous["status_code"] if anonymous else None
                ),
                context_statuses=tuple(
                    sorted(
                        (
                            name,
                            int(result["status_code"]),
                        )
                        for name, result in authenticated.items()
                    )
                ),
                authenticated_responses_differ=(
                    len(auth_fingerprints) > 1
                ),
            )
        )

    return comparisons
