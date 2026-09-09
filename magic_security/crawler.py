from __future__ import annotations

from collections import deque
from urllib.parse import urldefrag, urljoin

import httpx

from magic_security.transport import SecureTransport
from bs4 import BeautifulSoup

from magic_security.discovery import (
    extract_js_endpoints,
    extract_source_maps,
    parameter_names,
    same_origin,
)
from magic_security.models import CrawlResult, EndpointCandidate, PageSnapshot


HTML_TYPES = ("text/html", "application/xhtml+xml")
JS_TYPES = ("javascript", "ecmascript")


def _normalize_url(url: str) -> str:
    if "://" not in url:
        url = f"http://{url}"
    clean, _ = urldefrag(url)
    return clean.rstrip("/") or clean


class HttpCrawler:
    def __init__(
        self,
        max_pages: int = 100,
        max_js_assets: int = 100,
        timeout: float = 8.0,
    ) -> None:
        self.max_pages = max_pages
        self.max_js_assets = max_js_assets
        self.timeout = timeout

    async def crawl(
        self,
        target: str,
        *,
        scan_context: object | None = None,
    ) -> CrawlResult:
        target = _normalize_url(target)
        result = CrawlResult(target=target)
        queue: deque[str] = deque([target])
        seen: set[str] = set()
        metrics = getattr(scan_context, "metrics", None)
        budgets = getattr(scan_context, "budgets", None)

        async with SecureTransport(
            follow_redirects=True,
            timeout=self.timeout,
            headers={"User-Agent": "Magic-Security/0.2 local-security-scanner"},
        ) as client:
            while queue and len(seen) < self.max_pages:
                if scan_context is not None and getattr(
                    scan_context,
                    "is_cancelled",
                    lambda: False,
                )():
                    break
                if budgets is not None and budgets.exhausted:
                    break
                url = queue.popleft()
                if url in seen or not same_origin(url, target):
                    continue
                seen.add(url)

                if budgets is not None and not budgets.consume_page(self.max_pages):
                    break
                if budgets is not None and not budgets.consume_request(url):
                    break

                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue

                if metrics is not None:
                    metrics.requests += 1
                    metrics.pages += 1

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
                    params = parameter_names(candidate)
                    result.parameters.update(params)
                    if params:
                        result.endpoints.add(
                            EndpointCandidate(
                                url=candidate,
                                method="GET",
                                source="html:link",
                                parameters=params,
                            )
                        )
                    if same_origin(candidate, target) and candidate not in seen:
                        queue.append(candidate)

                for tag in soup.find_all("script", src=True):
                    asset = _normalize_url(urljoin(str(response.url), tag["src"]))
                    if same_origin(asset, target):
                        result.js_assets.add(asset)

                for tag in soup.find_all("script"):
                    if tag.get("src"):
                        continue
                    text = tag.string or tag.get_text(" ", strip=False)
                    discovered = extract_js_endpoints(text, str(response.url))
                    result.endpoints.update(discovered)
                    for endpoint in discovered:
                        result.parameters.update(endpoint.parameters)

                for form in soup.find_all("form"):
                    action = _normalize_url(urljoin(str(response.url), form.get("action") or str(response.url)))
                    method = (form.get("method") or "GET").upper()
                    names = tuple(
                        sorted(
                            {
                                field.get("name")
                                for field in form.find_all(["input", "select", "textarea", "button"])
                                if field.get("name")
                            }
                        )
                    )
                    result.forms.append(
                        {
                            "page": str(response.url),
                            "action": action,
                            "method": method,
                        }
                    )
                    if same_origin(action, target):
                        result.endpoints.add(
                            EndpointCandidate(
                                url=action,
                                method=method,
                                source="html:form",
                                parameters=names,
                            )
                        )
                        result.parameters.update(names)

            for asset_url in sorted(result.js_assets)[: self.max_js_assets]:
                if budgets is not None and not budgets.consume_request(asset_url):
                    break
                try:
                    response = await client.get(asset_url)
                except httpx.HTTPError:
                    continue
                if metrics is not None:
                    metrics.requests += 1
                if response.status_code != 200:
                    continue

                content_type = response.headers.get("content-type", "").lower()
                looks_like_js = any(marker in content_type for marker in JS_TYPES) or asset_url.lower().endswith((".js", ".mjs"))
                if not looks_like_js:
                    continue

                body = response.text[:1_000_000]
                discovered = extract_js_endpoints(body, asset_url)
                result.endpoints.update(discovered)
                result.source_maps.update(extract_source_maps(body, asset_url))
                for endpoint in discovered:
                    result.parameters.update(endpoint.parameters)

        return result
