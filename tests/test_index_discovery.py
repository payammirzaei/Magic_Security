import httpx
import pytest

from magic_security.index_discovery import discover_index_documents


@pytest.mark.asyncio
async def test_discovers_same_origin_robots_and_sitemap(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        if url.endswith("/robots.txt"):
            return httpx.Response(
                200,
                request=request,
                headers={"Content-Type": "text/plain"},
                text="Disallow: /admin\nAllow: /public\n",
            )
        return httpx.Response(
            200,
            request=request,
            text=(
                '<?xml version="1.0"?>'
                '<urlset>'
                '<url><loc>http://localhost/products</loc></url>'
                '<url><loc>https://example.com/external</loc></url>'
                '</urlset>'
            ),
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    result = await discover_index_documents("http://localhost")

    assert "http://localhost/admin" in result.links
    assert "http://localhost/public" in result.links
    assert "http://localhost/products" in result.links
    assert not any("example.com" in item for item in result.links)
    assert result.robots_entries == 2
    assert result.sitemap_entries == 1
