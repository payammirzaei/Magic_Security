import httpx
import pytest

from magic_security.exposure_pack import probe_sensitive_endpoints


@pytest.mark.asyncio
async def test_detects_backup_signature_without_storing_content(monkeypatch):
    class FakeStream:
        status_code = 200
        headers = {"content-type": "application/zip"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def aiter_bytes(self):
            yield b"PK\x03\x04fake-archive-secret-data"

    def fake_stream(self, method, url, **kwargs):
        if url.endswith("/backup.zip"):
            return FakeStream()

        class Empty(FakeStream):
            status_code = 404
            headers = {}

            async def aiter_bytes(self):
                yield b"not found"

        return Empty()

    async def fake_head(self, url, **kwargs):
        request = httpx.Request("HEAD", url)
        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)
    monkeypatch.setattr(httpx.AsyncClient, "head", fake_head)

    observations, findings = await probe_sensitive_endpoints(
        "http://localhost"
    )

    assert any(
        item.category == "backup_archive" and item.verified
        for item in observations
    )
    assert any("artifact" in item.title.lower() for item in findings)
    assert all("fake-archive-secret-data" not in item.evidence for item in findings)
