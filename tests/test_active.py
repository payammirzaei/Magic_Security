import httpx
import pytest

from magic_security.active import (
    _replace_query_parameter,
    verify_cors,
    verify_open_redirects,
)
from magic_security.models import EndpointCandidate, FindingKind


def test_replace_query_parameter_preserves_other_values():
    url = _replace_query_parameter(
        "http://localhost/go?next=%2Fhome&lang=en",
        "next",
        "https://magic-security.invalid/verified-redirect",
    )
    assert "lang=en" in url
    assert "next=https%3A%2F%2Fmagic-security.invalid%2Fverified-redirect" in url


@pytest.mark.asyncio
async def test_verified_cors_reflection(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={
                "Access-Control-Allow-Origin": "https://magic-security.invalid",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    findings = await verify_cors(["http://localhost/api/me"])

    assert len(findings) == 1
    assert findings[0].verified
    assert findings[0].kind is FindingKind.EXPOSURE
    assert findings[0].severity.value == "high"


@pytest.mark.asyncio
async def test_verified_open_redirect(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            302,
            request=request,
            headers={
                "Location": "https://magic-security.invalid/verified-redirect"
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    endpoint = EndpointCandidate(
        url="http://localhost/go?next=/home",
        method="GET",
        source="html:link",
        parameters=("next",),
    )

    findings = await verify_open_redirects([endpoint])

    assert len(findings) == 1
    assert findings[0].verified
    assert findings[0].kind is FindingKind.VULNERABILITY
    assert "HTTP 302" in findings[0].evidence


@pytest.mark.asyncio
async def test_open_redirect_ignores_non_redirect_parameters(monkeypatch):
    called = False

    async def fake_get(self, url, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("Should not send a probe")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    endpoint = EndpointCandidate(
        url="http://localhost/products?page=2",
        method="GET",
        source="html:link",
        parameters=("page",),
    )

    findings = await verify_open_redirects([endpoint])
    assert findings == []
    assert called is False
