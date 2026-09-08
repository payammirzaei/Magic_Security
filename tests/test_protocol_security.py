import httpx
import pytest

from magic_security.protocol_security import analyze_protocol_security


@pytest.mark.asyncio
async def test_trace_reflection_is_reported(monkeypatch):
    async def fake_request(self, method, url, **kwargs):
        request = httpx.Request(method, url)
        if method == "TRACE":
            return httpx.Response(
                200,
                request=request,
                text="X-Magic-Security-Trace: magic-security-trace-marker",
            )
        raise AssertionError(method)

    async def fake_get(self, url, **kwargs):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            headers={"Server": "Demo/1.0"},
            text="ok",
        )

    async def fake_options(self, url, **kwargs):
        return httpx.Response(
            204,
            request=httpx.Request("OPTIONS", url),
            headers={"Allow": "GET, POST, TRACE"},
        )

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(httpx.AsyncClient, "options", fake_options)

    observations, findings = await analyze_protocol_security(
        "http://localhost"
    )

    assert any(item.category == "trace_method" for item in observations)
    assert any(
        finding.title == "HTTP TRACE method reflects request data"
        for finding in findings
    )
