import httpx
import pytest

from magic_security.classifier import classify_endpoints
from magic_security.models import FindingKind, NormalizedEndpoint


@pytest.mark.asyncio
async def test_classifier_marks_auth_required(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(401, request=request, json={"detail": "login"})

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await classify_endpoints(
        [
            NormalizedEndpoint(
                url="http://localhost/api/private",
                method="GET",
            )
        ]
    )

    assert len(observations) == 1
    assert observations[0].classification == "auth_required"
    assert findings == []


@pytest.mark.asyncio
async def test_classifier_reports_sensitive_json_without_values(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            json={
                "users": [
                    {
                        "email": "alice@example.test",
                        "phone": "+491234567",
                        "name": "Alice",
                    }
                ]
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await classify_endpoints(
        [
            NormalizedEndpoint(
                url="http://localhost/api/users",
                method="GET",
            )
        ]
    )

    assert observations[0].classification == "json"
    assert observations[0].sensitive_fields == (
        "users.email",
        "users.phone",
    )
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.EXPOSURE
    assert findings[0].verified
    assert "alice@example.test" not in findings[0].evidence
    assert "+491234567" not in findings[0].evidence


@pytest.mark.asyncio
async def test_classifier_skips_path_templates(monkeypatch):
    called = False

    async def fake_get(self, url, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("template endpoint should not be requested")

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await classify_endpoints(
        [
            NormalizedEndpoint(
                url="http://localhost/api/users/{user_id}",
                method="GET",
            )
        ]
    )

    assert observations == []
    assert findings == []
    assert called is False
