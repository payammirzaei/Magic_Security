"""STEP 58 — auth identity integrity."""

from __future__ import annotations

import pytest

from magic_security.auth import AuthConfigError
from magic_security.auth_context import (
    AuthIdentityValidation,
    IdentityProbeResult,
    validate_auth_identities,
)
from magic_security.models import AuthContext


@pytest.mark.asyncio
async def test_duplicate_cookie_identities_rejected(monkeypatch):
    async def fake_probe(target, context, *, timeout=5.0):
        return IdentityProbeResult(
            context=context.name,
            path="/api/me",
            status_code=200,
            fingerprint="same-fp",
            marker_matched=True,
        )

    monkeypatch.setattr(
        "magic_security.auth_context.probe_context_identity",
        fake_probe,
    )
    contexts = [
        AuthContext(name="A", cookies={"s": "1"}, role="user"),
        AuthContext(name="B", cookies={"s": "1"}, role="user"),
    ]
    result = await validate_auth_identities("http://127.0.0.1:8000/", contexts)
    assert result.duplicate_identities
    assert len(result.valid_contexts) < 2


@pytest.mark.asyncio
async def test_expired_session_rejected(monkeypatch):
    async def fake_probe(target, context, *, timeout=5.0):
        return IdentityProbeResult(
            context=context.name,
            path="/api/me",
            status_code=401,
            fingerprint="x",
            expired=True,
        )

    monkeypatch.setattr(
        "magic_security.auth_context.probe_context_identity",
        fake_probe,
    )
    contexts = [
        AuthContext(name="A", cookies={"s": "a"}),
        AuthContext(name="B", cookies={"s": "b"}),
    ]
    result = await validate_auth_identities("http://127.0.0.1:8000/", contexts)
    assert result.expired_sessions
    assert result.valid_contexts == []


@pytest.mark.asyncio
async def test_marker_mismatch_rejected(monkeypatch):
    async def fake_probe(target, context, *, timeout=5.0):
        return IdentityProbeResult(
            context=context.name,
            path="/api/me",
            status_code=200,
            fingerprint=context.name + "-fp",
            marker_matched=False,
        )

    monkeypatch.setattr(
        "magic_security.auth_context.probe_context_identity",
        fake_probe,
    )
    contexts = [
        AuthContext(
            name="A",
            cookies={"s": "a"},
            expected_identity_marker="user-A",
        ),
        AuthContext(
            name="B",
            cookies={"s": "b"},
            expected_identity_marker="user-B",
        ),
    ]
    result = await validate_auth_identities("http://127.0.0.1:8000/", contexts)
    assert any("marker" in r for r in result.rejected_reasons)


@pytest.mark.asyncio
async def test_requires_two_contexts():
    with pytest.raises(AuthConfigError):
        await validate_auth_identities(
            "http://127.0.0.1:8000/",
            [AuthContext(name="only", cookies={"s": "1"})],
        )


def test_validation_dict_safe():
    v = AuthIdentityValidation(duplicate_identities=True)
    assert v.to_dict()["duplicate_identities"] is True
