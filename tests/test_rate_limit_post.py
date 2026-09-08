import httpx
import pytest

from magic_security.behavior_security import classify_rate_limits
from magic_security.models import NormalizedEndpoint


@pytest.mark.asyncio
async def test_login_post_rate_probe_uses_synthetic_credentials(monkeypatch):
    captured = []

    async def fake_post(self, url, **kwargs):
        captured.append(kwargs["json"])
        request = httpx.Request("POST", url)
        return httpx.Response(
            401,
            request=request,
            json={"detail": "invalid"},
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    observations = await classify_rate_limits(
        [
            NormalizedEndpoint(
                url="http://localhost/api/login",
                method="POST",
            )
        ],
        requests_per_endpoint=2,
    )

    assert observations[0].method == "POST"
    assert len(captured) == 2
    assert captured[0]["email"].endswith("@example.invalid")
    assert "real" not in captured[0]["email"]
