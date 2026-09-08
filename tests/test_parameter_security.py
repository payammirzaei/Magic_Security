import httpx
import pytest

from magic_security.models import NormalizedEndpoint
from magic_security.parameter_security import verify_parameter_security


@pytest.mark.asyncio
async def test_ssti_is_verified_without_dangerous_payload(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if "%7B%7B1337%2A7%7D%7D" in url:
            return httpx.Response(200, request=request, text="Hello 9359")
        return httpx.Response(200, request=request, text="Hello baseline")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_parameter_security(
        [
            NormalizedEndpoint(
                url="http://localhost/render",
                method="GET",
                parameters=("name",),
            )
        ]
    )

    assert any(
        item.category == "ssti" and item.verified
        for item in observations
    )
    assert any(
        finding.title == "Server-side template injection verified"
        for finding in findings
    )


@pytest.mark.asyncio
async def test_database_error_is_exposure_not_sql_injection_claim(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if "magic-security-%27" in url:
            return httpx.Response(
                500,
                request=request,
                text="PostgreSQL ERROR: syntax error",
            )
        return httpx.Response(200, request=request, text="ok")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    _, findings = await verify_parameter_security(
        [
            NormalizedEndpoint(
                url="http://localhost/search",
                method="GET",
                parameters=("q",),
            )
        ]
    )

    assert any(
        finding.title == "Input triggers a database error response"
        and finding.kind.value == "exposure"
        for finding in findings
    )


@pytest.mark.asyncio
async def test_crlf_header_injection_is_verified(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if "X-Magic-Security-Probe" in url:
            return httpx.Response(
                200,
                request=request,
                headers={"X-Magic-Security-Probe": "verified"},
                text="ok",
            )
        return httpx.Response(200, request=request, text="ok")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_parameter_security(
        [
            NormalizedEndpoint(
                url="http://localhost/redirect",
                method="GET",
                parameters=("next",),
            )
        ]
    )

    assert any(
        item.category == "crlf_header_injection" and item.verified
        for item in observations
    )
    assert any(
        finding.title == "HTTP response header injection verified"
        for finding in findings
    )
