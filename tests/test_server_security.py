import httpx
import pytest

from magic_security.models import NormalizedEndpoint
from magic_security.server_security import (
    verify_auth_injection_bypass,
    verify_host_header_poisoning,
    verify_path_traversal,
)


@pytest.mark.asyncio
async def test_path_traversal_marker_is_verified(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if "etc%2Fhosts" in url:
            return httpx.Response(
                200,
                request=request,
                text="127.0.0.1 localhost",
            )
        return httpx.Response(
            404,
            request=request,
            text="not found",
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_path_traversal(
        [
            NormalizedEndpoint(
                url="http://localhost/download",
                method="GET",
                parameters=("file",),
            )
        ]
    )

    assert any(item.verified for item in observations)
    assert any(
        "Path traversal" in item.title
        for item in findings
    )


@pytest.mark.asyncio
async def test_sql_auth_bypass_requires_success_signal(monkeypatch):
    async def fake_post(self, url, **kwargs):
        request = httpx.Request("POST", url)
        email = kwargs["json"]["email"]

        if isinstance(email, str) and "OR" in email:
            return httpx.Response(
                200,
                request=request,
                headers={
                    "Set-Cookie": "demo_session=A; Path=/"
                },
                json={"user": {"id": "A"}},
            )

        return httpx.Response(
            401,
            request=request,
            json={"detail": "invalid"},
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    observations, findings = await verify_auth_injection_bypass(
        [
            NormalizedEndpoint(
                url="http://localhost/api/login",
                method="POST",
            )
        ]
    )

    assert any(
        item.category == "auth_sqli" and item.verified
        for item in observations
    )
    assert any(
        "authentication bypass" in item.title.lower()
        for item in findings
    )


@pytest.mark.asyncio
async def test_host_header_influence_is_exposure(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        host = kwargs.get("headers", {}).get(
            "X-Forwarded-Host"
        )
        body = (
            f"http://{host}/landing"
            if host
            else "http://localhost/landing"
        )
        return httpx.Response(
            200,
            request=request,
            text=body,
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_host_header_poisoning(
        ["http://localhost/absolute"]
    )

    assert observations[0].verified is True
    assert any(
        "Host header" in item.title
        for item in findings
    )
