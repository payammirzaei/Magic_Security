from __future__ import annotations

from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from magic_security.models import CrawlResult, PageSnapshot


HTML_TYPES = ("text/html", "application/xhtml+xml")


def _normalize_url(url: str) -> str:
    if "://" not in url:
        url = f"http://{url}"
    clean, _ = urldefrag(url)
    return clean.rstrip("/") or clean


def _same_origin(candidate: str, origin: str) -> bool:
    a = urlparse(candidate)
    b = urlparse(origin)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


class HttpCrawler:
    def __init__(self, max_pages: int = 100, timeout: float = 8.0) -> None:
        self.max_pages = max_pages
        self.timeout = timeout

    async def crawl(self, target: str) -> CrawlResult:
        target = _normalize_url(target)
        result = CrawlResult(target=target)
        queue: deque[str] = deque([target])
        seen: set[str] = set()

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            headers={"User-Agent": "Magic-Security/0.1 local-security-scanner"},
        ) as client:
            while queue and len(seen) < self.max_pages:
                url = queue.popleft()
                if url in seen or not _same_origin(url, target):
                    continue
                seen.add(url)

                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue

                content_type = response.headers.get("content-type", "").lower()
                body = response.text if any(t in content_type for t in HTML_TYPES) else ""

                page = PageSnapshot(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    set_cookies=response.headers.get_list("set-cookie"),
                    content_type=content_type,
                    body=body,
                )
                result.pages.append(page)

                if not body:
                    continue

                soup = BeautifulSoup(body, "html.parser")

                for tag in soup.find_all("a", href=True):
                    candidate = _normalize_url(urljoin(str(response.url), tag["href"]))
                    result.links.add(candidate)
                    if _same_origin(candidate, target) and candidate not in seen:
                        queue.append(candidate)

                for tag in soup.find_all("script", src=True):
                    asset = _normalize_url(urljoin(str(response.url), tag["src"]))
                    if _same_origin(asset, target):
                        result.js_assets.add(asset)

                for form in soup.find_all("form"):
                    action = _normalize_url(urljoin(str(response.url), form.get("action") or str(response.url)))
                    result.forms.append(
                        {
                            "page": str(response.url),
                            "action": action,
                            "method": (form.get("method") or "GET").upper(),
                        }
                    )

        return result
