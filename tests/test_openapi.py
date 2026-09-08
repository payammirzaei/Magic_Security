import httpx
import pytest

from magic_security.openapi import discover_openapi_endpoints, parse_openapi_document


def test_parse_openapi_document_extracts_methods_and_parameters():
    document = {
        "openapi": "3.1.0",
        "paths": {
            "/users/{user_id}": {
                "parameters": [{"name": "user_id", "in": "path"}],
                "get": {
                    "parameters": [{"name": "include", "in": "query"}],
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                },
            }
        },
    }

    endpoints = parse_openapi_document(document, "http://localhost:8000")
    compact = {
        (item.method, item.url, item.parameters)
        for item in endpoints
    }

    assert (
        "GET",
        "http://localhost:8000/users/{user_id}",
        ("include", "user_id"),
    ) in compact
    assert (
        "POST",
        "http://localhost:8000/users/{user_id}",
        ("email", "name", "user_id"),
    ) in compact


@pytest.mark.asyncio
async def test_discover_openapi_endpoints(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if url.endswith("/openapi.json"):
            return httpx.Response(
                200,
                request=request,
                json={
                    "openapi": "3.1.0",
                    "paths": {"/health": {"get": {}}},
                },
            )
        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    endpoints = await discover_openapi_endpoints("http://localhost:8000")

    assert any(
        item.url == "http://localhost:8000/health"
        and item.method == "GET"
        and item.source == "openapi"
        for item in endpoints
    )
