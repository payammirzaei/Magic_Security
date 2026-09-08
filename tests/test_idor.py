import httpx
import pytest

from magic_security.idor import (
    verify_idor_read_access,
    verify_pairwise_idor_read_access,
)
from magic_security.models import (
    AuthComparison,
    AuthContext,
    FindingKind,
    NormalizedEndpoint,
)


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
    assert len(findings) >= 1
    assert findings[0].kind is FindingKind.VULNERABILITY
    assert findings[0].verified
    assert "101" not in findings[0].evidence
    assert "202" not in findings[0].evidence


@pytest.mark.asyncio
async def test_query_parameter_idor_is_verified(monkeypatch):
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

        if "/api/account-detail" in url:
            account_id = int(url.split("account_id=", 1)[1].split("&", 1)[0])
            return httpx.Response(
                200,
                request=request,
                json={"account_id": account_id, "plan": "demo"},
            )

        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    endpoints = [
        NormalizedEndpoint(url="http://localhost/api/me", method="GET"),
        NormalizedEndpoint(
            url="http://localhost/api/account-detail",
            method="GET",
            parameters=("account_id",),
        ),
    ]
    contexts = [
        AuthContext(name="user_a", headers={"X-Test-User": "A"}),
        AuthContext(name="user_b", headers={"X-Test-User": "B"}),
    ]

    ownership, observations, findings = await verify_pairwise_idor_read_access(
        endpoints,
        contexts,
        auth_comparisons=[
            AuthComparison(
                url="http://localhost/api/me",
                method="GET",
                boundary="protected",
                anonymous_status=401,
                context_statuses=(("user_a", 200), ("user_b", 200)),
                authenticated_responses_differ=True,
            )
        ],
    )

    assert any(item.parameter == "account_id" for item in ownership)
    assert any(
        item.parameter_location == "query"
        and item.cross_account_verified
        for item in observations
    )
    assert any(item.kind is FindingKind.VULNERABILITY for item in findings)


@pytest.mark.asyncio
async def test_roles_limit_pairwise_idor_to_same_role(monkeypatch):
    ids = {"A": 101, "B": 202, "ADMIN": 303}

    async def fake_get(self, url, **kwargs):
        marker = self.headers.get("X-Test-User")
        request = httpx.Request("GET", url)

        if url.endswith("/api/me"):
            return httpx.Response(
                200,
                request=request,
                json={"account_id": ids[marker]},
            )

        if "/api/accounts/" in url:
            account_id = int(url.rsplit("/", 1)[-1])
            return httpx.Response(
                200,
                request=request,
                json={"account_id": account_id},
            )

        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    contexts = [
        AuthContext(
            name="user_a",
            headers={"X-Test-User": "A"},
            role="customer",
        ),
        AuthContext(
            name="user_b",
            headers={"X-Test-User": "B"},
            role="customer",
        ),
        AuthContext(
            name="admin",
            headers={"X-Test-User": "ADMIN"},
            role="admin",
        ),
    ]
    endpoints = [
        NormalizedEndpoint(url="http://localhost/api/me", method="GET"),
        NormalizedEndpoint(
            url="http://localhost/api/accounts/{account_id}",
            method="GET",
        ),
    ]

    _, observations, _ = await verify_pairwise_idor_read_access(
        endpoints,
        contexts,
    )

    pairs = {
        (item.owner_context, item.requester_context)
        for item in observations
    }
    assert ("user_a", "user_b") in pairs
    assert ("user_b", "user_a") in pairs
    assert ("user_a", "admin") not in pairs
    assert ("admin", "user_b") not in pairs
