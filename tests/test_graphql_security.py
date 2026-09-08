import httpx
import pytest

from magic_security.graphql_security import analyze_graphql
from magic_security.models import NormalizedEndpoint


@pytest.mark.asyncio
async def test_anonymous_graphql_introspection(monkeypatch):
    async def fake_post(self, url, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            request=request,
            json={
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                    }
                }
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    observations, findings = await analyze_graphql(
        [NormalizedEndpoint(url="http://localhost/graphql", method="POST")]
    )

    assert observations[0].anonymous_introspection is True
    assert any("introspection" in finding.title.lower() for finding in findings)


@pytest.mark.asyncio
async def test_graphql_debug_error_is_detected(monkeypatch):
    async def fake_post(self, url, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(
            400,
            request=request,
            json={
                "errors": [
                    {
                        "message": "bad query",
                        "extensions": {"stacktrace": ["internal.py:42"]},
                    }
                ]
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    observations, findings = await analyze_graphql(
        [NormalizedEndpoint(url="http://localhost/graphql", method="POST")]
    )

    assert observations[0].detailed_errors is True
    assert any("debug" in finding.title.lower() for finding in findings)
