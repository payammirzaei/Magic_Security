import httpx
import pytest

from magic_security.idor import verify_idor_read_access
from magic_security.models import AuthContext, FindingKind, NormalizedEndpoint


@pytest.mark.asyncio
async def test_verified_cross_account_read(monkeypatch):
    async def fake_get(self, url, **kwargs):
        marker = self.headers.get("X-Test-User")
        request = httpx.Request("GET", url)

        if url.endswith("/api/me"):
            account_id = 101 if marker == "A" else 202
            return httpx.Response(
                200,
                request=request,
                json={"account_id": account_id},
            )

        if "/api/accounts/" in url:
            account_id = int(url.rsplit("/", 1)[-1])
            return httpx.Response(
                200,
                request=request,
                json={
                    "account_id": account_id,
                    "email": f"user-{account_id}@example.test",
                },
            )

        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    endpoints = [
        NormalizedEndpoint(
            url="http://localhost/api/me",
            method="GET",
        ),
        NormalizedEndpoint(
            url="http://localhost/api/accounts/{account_id}",
            method="GET",
        ),
    ]
    contexts = [
        AuthContext(name="user_a", headers={"X-Test-User": "A"}),
        AuthContext(name="user_b", headers={"X-Test-User": "B"}),
    ]

    observations, findings = await verify_idor_read_access(
        endpoints,
        contexts,
    )

    assert len(observations) == 1
    assert observations[0].cross_account_verified is True
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.VULNERABILITY
    assert findings[0].verified
    assert "101" not in findings[0].evidence
    assert "202" not in findings[0].evidence


@pytest.mark.asyncio
async def test_correct_object_authorization_is_not_reported(monkeypatch):
    async def fake_get(self, url, **kwargs):
        marker = self.headers.get("X-Test-User")
        request = httpx.Request("GET", url)
        own_id = 101 if marker == "A" else 202

        if url.endswith("/api/me"):
            return httpx.Response(
                200,
                request=request,
                json={"account_id": own_id},
            )

        if "/api/accounts/" in url:
            requested_id = int(url.rsplit("/", 1)[-1])
            if requested_id != own_id:
                return httpx.Response(
                    403,
                    request=request,
                    json={"detail": "forbidden"},
                )
            return httpx.Response(
                200,
                request=request,
                json={"account_id": requested_id},
            )

        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    endpoints = [
        NormalizedEndpoint(
            url="http://localhost/api/me",
            method="GET",
        ),
        NormalizedEndpoint(
            url="http://localhost/api/accounts/{account_id}",
            method="GET",
        ),
    ]
    contexts = [
        AuthContext(name="user_a", headers={"X-Test-User": "A"}),
        AuthContext(name="user_b", headers={"X-Test-User": "B"}),
    ]

    observations, findings = await verify_idor_read_access(
        endpoints,
        contexts,
    )

    assert observations[0].cross_account_verified is False
    assert observations[0].user_b_to_a_status == 403
    assert observations[0].user_a_to_b_status == 403
    assert findings == []


@pytest.mark.asyncio
async def test_no_bruteforce_when_user_ids_are_not_observed(monkeypatch):
    calls: list[str] = []

    async def fake_get(self, url, **kwargs):
        calls.append(url)
        request = httpx.Request("GET", url)
        if url.endswith("/api/me"):
            return httpx.Response(
                200,
                request=request,
                json={"display_name": "Demo"},
            )
        raise AssertionError("Template should not be probed without owned IDs")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    endpoints = [
        NormalizedEndpoint(
            url="http://localhost/api/me",
            method="GET",
        ),
        NormalizedEndpoint(
            url="http://localhost/api/accounts/{account_id}",
            method="GET",
        ),
    ]
    contexts = [
        AuthContext(name="user_a", headers={"X-Test-User": "A"}),
        AuthContext(name="user_b", headers={"X-Test-User": "B"}),
    ]

    observations, findings = await verify_idor_read_access(
        endpoints,
        contexts,
    )

    assert observations == []
    assert findings == []
    assert calls == [
        "http://localhost/api/me",
        "http://localhost/api/me",
    ]
