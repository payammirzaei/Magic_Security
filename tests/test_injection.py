import httpx
import pytest

from magic_security.injection import verify_reflected_html_injection
from magic_security.models import FindingKind, NormalizedEndpoint


@pytest.mark.asyncio
async def test_reflected_html_injection_is_verified(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(url).query).get("q", [""])[0]
        return httpx.Response(
            200,
            request=request,
            headers={"Content-Type": "text/html"},
            text=f"<html><body>{q}</body></html>",
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_reflected_html_injection(
        [
            NormalizedEndpoint(
                url="http://localhost/search",
                method="GET",
                parameters=("q",),
            )
        ]
    )

    assert observations[0].html_injection_verified is True
    assert findings[0].kind is FindingKind.VULNERABILITY
    assert findings[0].verified


@pytest.mark.asyncio
async def test_encoded_reflection_is_not_html_injection(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={"Content-Type": "text/html"},
            text="<html><body>&lt;ms-security-probe&gt;</body></html>",
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_reflected_html_injection(
        [
            NormalizedEndpoint(
                url="http://localhost/search",
                method="GET",
                parameters=("q",),
            )
        ]
    )

    assert findings == []
