import httpx
import pytest

from magic_security.client_artifacts import analyze_client_artifacts


@pytest.mark.asyncio
async def test_client_secret_names_are_reported_without_values(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            text=(
                'const API_SECRET = "very-secret-demo-value";\n'
                'const INTERNAL = "http://10.0.0.5/private";'
            ),
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    observations, findings = await analyze_client_artifacts(
        ["http://localhost/app.js"],
        [],
    )

    assert observations[0].secret_like_names == ("API_SECRET",)
    evidence = " ".join(item.evidence for item in findings)
    assert "very-secret-demo-value" not in evidence
    assert any("internal network" in item.title.lower() for item in findings)
