import json

import httpx
import pytest

from magic_security.auth import load_auth_contexts, map_auth_boundaries
from magic_security.models import NormalizedEndpoint


def test_load_auth_contexts(tmp_path):
    path = tmp_path / "auth.json"
    path.write_text(
        json.dumps(
            {
                "contexts": [
                    {
                        "name": "user_a",
                        "headers": {"X-Test-User": "A"},
                    },
                    {
                        "name": "user_b",
                        "cookies": {"session": "fake-b"},
                    },
                ]
            }
        )
    )

    contexts = load_auth_contexts(path)

    assert [item.name for item in contexts] == ["user_a", "user_b"]
    assert contexts[0].headers["X-Test-User"] == "A"
    assert contexts[1].cookies["session"] == "fake-b"


@pytest.mark.asyncio
async def test_auth_boundary_detects_protected_endpoint(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        marker = self.headers.get("X-Test-User")
        if not marker:
            return httpx.Response(401, request=request, json={"detail": "login"})
        return httpx.Response(
            200,
            request=request,
            json={"user": marker},
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    from magic_security.models import AuthContext

    comparisons = await map_auth_boundaries(
        [
            NormalizedEndpoint(
                url="http://localhost/api/me",
                method="GET",
            )
        ],
        [
            AuthContext(name="user_a", headers={"X-Test-User": "A"}),
            AuthContext(name="user_b", headers={"X-Test-User": "B"}),
        ],
    )

    assert len(comparisons) == 1
    item = comparisons[0]
    assert item.boundary == "protected"
    assert item.anonymous_status == 401
    assert item.authenticated_responses_differ is True


@pytest.mark.asyncio
async def test_auth_boundary_marks_public_or_unprotected(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            json={"public": True},
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    from magic_security.models import AuthContext

    comparisons = await map_auth_boundaries(
        [
            NormalizedEndpoint(
                url="http://localhost/api/public",
                method="GET",
            )
        ],
        [
            AuthContext(name="user_a"),
            AuthContext(name="user_b"),
        ],
    )

    assert comparisons[0].boundary == "public_or_unprotected"
    assert comparisons[0].authenticated_responses_differ is False
