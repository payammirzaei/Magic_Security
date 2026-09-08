import httpx
import pytest

from magic_security.models import AuthContext, FindingKind, NormalizedEndpoint
from magic_security.session_security import analyze_session_cookies


@pytest.mark.asyncio
async def test_session_cookie_analysis_redacts_values(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={
                "Set-Cookie": "demo_session=super-secret; Path=/"
            },
            text="ok",
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await analyze_session_cookies(
        [NormalizedEndpoint(url="http://localhost/dashboard", method="GET")],
        [AuthContext(name="user_a", headers={"X-Test-User": "A"})],
    )

    assert len(observations) == 1
    assert observations[0].cookie_name == "demo_session"
    assert observations[0].httponly is False
    assert observations[0].same_site is None
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HARDENING
    assert "super-secret" not in findings[0].evidence


@pytest.mark.asyncio
async def test_secure_session_cookie_does_not_create_finding(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={
                "Set-Cookie": (
                    "session=abc; Path=/; HttpOnly; Secure; SameSite=Lax"
                )
            },
            text="ok",
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await analyze_session_cookies(
        [NormalizedEndpoint(url="http://localhost/dashboard", method="GET")],
        [AuthContext(name="user_a")],
    )

    assert observations[0].secure is True
    assert observations[0].httponly is True
    assert observations[0].same_site == "lax"
    assert findings == []
