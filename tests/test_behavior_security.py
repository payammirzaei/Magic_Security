import httpx
import pytest

from magic_security.behavior_security import (
    analyze_authenticated_cache,
    classify_rate_limits,
    verify_protected_cors,
)
from magic_security.models import AuthComparison, AuthContext, NormalizedEndpoint


@pytest.mark.asyncio
async def test_protected_credentialed_cors_is_exposure(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={
                "Access-Control-Allow-Origin": "https://magic-security.invalid",
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "application/json",
            },
            json={"private": True},
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_protected_cors(
        [
            AuthComparison(
                url="http://localhost/api/me",
                method="GET",
                boundary="protected",
                anonymous_status=401,
            )
        ],
        [AuthContext(name="user_a", cookies={"session": "fake"})],
    )

    assert observations[0].protected_response_exposed is True
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_user_specific_public_cache_is_reported(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={"Cache-Control": "public, max-age=300"},
            json={"user": "demo"},
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await analyze_authenticated_cache(
        [
            AuthComparison(
                url="http://localhost/api/me",
                method="GET",
                boundary="protected",
                anonymous_status=401,
                authenticated_responses_differ=True,
            )
        ],
        [AuthContext(name="user_a", cookies={"session": "fake"})],
    )

    assert observations[0].risky_shared_cache is True
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_rate_limit_observation_stops_on_429(monkeypatch):
    calls = 0

    async def fake_get(self, url, **kwargs):
        nonlocal calls
        calls += 1
        request = httpx.Request("GET", url)
        status = 429 if calls == 4 else 200
        headers = {"Retry-After": "60"} if status == 429 else {}
        return httpx.Response(status, request=request, headers=headers, text="ok")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations = await classify_rate_limits(
        [NormalizedEndpoint(url="http://localhost/api/public", method="GET")],
        requests_per_endpoint=6,
    )

    assert observations[0].throttled is True
    assert observations[0].requests_sent == 4
    assert "retry-after" in observations[0].rate_limit_headers
