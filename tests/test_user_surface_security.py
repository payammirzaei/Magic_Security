import httpx
import pytest

from magic_security.models import NormalizedEndpoint, PageSnapshot
from magic_security.user_surface_security import (
    analyze_user_visible_surface,
    verify_jsonp_and_null_origin_cors,
)


def test_sensitive_url_and_get_form_are_reported_without_values():
    observations, findings = analyze_user_visible_surface(
        target="http://localhost",
        pages=[],
        links={"http://localhost/reset?token=super-secret-token"},
        endpoints=[
            NormalizedEndpoint(
                url="http://localhost/login",
                method="GET",
                parameters=("username", "password"),
                sources=("browser:form",),
            )
        ],
    )

    assert any(item.category == "sensitive_url_parameter" for item in observations)
    assert any(item.category == "sensitive_get_form" for item in observations)
    assert all("super-secret-token" not in item.evidence for item in findings)


def test_mixed_content_on_https_is_detected():
    page = PageSnapshot(
        url="https://localhost/",
        status_code=200,
        headers={},
        set_cookies=[],
        content_type="text/html",
        body='<script src="http://localhost/app.js"></script>',
    )

    observations, findings = analyze_user_visible_surface(
        target="https://localhost",
        pages=[page],
        links=set(),
        endpoints=[],
    )

    assert observations[0].category == "mixed_content"
    assert findings[0].severity.value == "medium"


@pytest.mark.asyncio
async def test_null_origin_and_jsonp_are_verified(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if (kwargs.get("headers") or {}).get("Origin") == "null":
            return httpx.Response(
                200,
                request=request,
                headers={
                    "Access-Control-Allow-Origin": "null",
                    "Access-Control-Allow-Credentials": "true",
                },
                json={"ok": True},
            )
        return httpx.Response(
            200,
            request=request,
            headers={"Content-Type": "application/javascript"},
            text='magicSecurityCallback({"ok":true});',
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await verify_jsonp_and_null_origin_cors(
        [
            NormalizedEndpoint(
                url="http://localhost/data",
                method="GET",
                parameters=("callback",),
            )
        ]
    )

    assert any(
        item.category == "null_origin_cors" and item.verified
        for item in observations
    )
    assert any(
        item.category == "jsonp" and item.verified
        for item in observations
    )
    assert len(findings) == 2
