"""Authentication Context Model v2 (STEP 27)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from magic_security.auth import AuthConfigError, load_auth_contexts as _load_auth_contexts
from magic_security.models import AuthContext
from magic_security.transport import open_secure_transport


_IDENTITY_PATHS = (
    "/api/me",
    "/me",
    "/api/user",
    "/api/users/me",
    "/api/account",
)


@dataclass
class IdentityProbeResult:
    context: str
    path: str | None
    status_code: int | None
    fingerprint: str | None
    marker_matched: bool | None = None
    expired: bool = False
    error: str | None = None


@dataclass
class AuthIdentityValidation:
    valid_contexts: list[AuthContext] = field(default_factory=list)
    probes: list[IdentityProbeResult] = field(default_factory=list)
    rejected_reasons: list[str] = field(default_factory=list)
    duplicate_identities: bool = False
    expired_sessions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid_contexts": [item.name for item in self.valid_contexts],
            "rejected_reasons": list(self.rejected_reasons),
            "duplicate_identities": self.duplicate_identities,
            "expired_sessions": list(self.expired_sessions),
            "probes": [
                {
                    "context": item.context,
                    "path": item.path,
                    "status_code": item.status_code,
                    "fingerprint": item.fingerprint,
                    "marker_matched": item.marker_matched,
                    "expired": item.expired,
                    "error": item.error,
                }
                for item in self.probes
            ],
        }


def load_auth_contexts_v2(path: str) -> list[AuthContext]:
    """Load auth contexts with v2 optional fields (backward compatible)."""
    return _load_auth_contexts(path)


def _identity_fingerprint(response: httpx.Response) -> str:
    content_type = response.headers.get("content-type", "").split(";", 1)[0]
    payload = (
        f"{response.status_code}\n{content_type.lower()}\n".encode("utf-8")
        + response.content[:200_000]
    )
    return hashlib.sha256(payload).hexdigest()[:16]


async def probe_context_identity(
    target: str,
    context: AuthContext,
    *,
    timeout: float = 5.0,
) -> IdentityProbeResult:
    paths = list(_IDENTITY_PATHS)
    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/1.1 identity-probe",
            "Accept": "application/json,*/*;q=0.5",
            **context.headers,
        },
        cookies=context.cookies,
    ) as client:
        for path in paths:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(url)
            except httpx.HTTPError as exc:
                return IdentityProbeResult(
                    context=context.name,
                    path=path,
                    status_code=None,
                    fingerprint=None,
                    error=type(exc).__name__,
                )
            if response.status_code in {401, 403}:
                return IdentityProbeResult(
                    context=context.name,
                    path=path,
                    status_code=response.status_code,
                    fingerprint=_identity_fingerprint(response),
                    expired=True,
                )
            if response.status_code == 404:
                continue
            if not (200 <= response.status_code < 300):
                continue

            marker_matched = None
            if context.expected_identity_marker:
                marker_matched = (
                    context.expected_identity_marker in response.text
                )
            return IdentityProbeResult(
                context=context.name,
                path=path,
                status_code=response.status_code,
                fingerprint=_identity_fingerprint(response),
                marker_matched=marker_matched,
            )

    return IdentityProbeResult(
        context=context.name,
        path=None,
        status_code=None,
        fingerprint=None,
        error="no_identity_endpoint",
    )


async def validate_auth_identities(
    target: str,
    contexts: list[AuthContext],
    *,
    timeout: float = 5.0,
) -> AuthIdentityValidation:
    if len(contexts) < 2:
        raise AuthConfigError(
            "Auth identity validation requires at least two contexts."
        )

    result = AuthIdentityValidation()
    fingerprints: dict[str, str] = {}

    for context in contexts:
        probe = await probe_context_identity(
            target,
            context,
            timeout=timeout,
        )
        result.probes.append(probe)

        if probe.expired:
            result.expired_sessions.append(context.name)
            result.rejected_reasons.append(
                f"{context.name}: expired or unauthorized session "
                f"(HTTP {probe.status_code})"
            )
            continue

        if context.expected_identity_marker and probe.marker_matched is False:
            result.rejected_reasons.append(
                f"{context.name}: expected_identity_marker not observed"
            )
            continue

        if probe.fingerprint is None:
            # No /api/me-style endpoint — keep context but note it.
            result.valid_contexts.append(context)
            continue

        prior = [
            name
            for name, fp in fingerprints.items()
            if fp == probe.fingerprint
        ]
        if prior:
            result.duplicate_identities = True
            result.rejected_reasons.append(
                f"{context.name}: duplicate identity fingerprint with "
                f"{prior[0]} (same session)"
            )
            continue

        fingerprints[context.name] = probe.fingerprint
        result.valid_contexts.append(context)

    return result
