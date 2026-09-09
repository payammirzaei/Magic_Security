from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

from magic_security.browser_security import storage_observations_from_keys
from magic_security.discovery import parameter_names, same_origin
from magic_security.models import (
    AuthContext,
    BrowserSecurityObservation,
    CrawlResult,
    EndpointCandidate,
)
from magic_security.transport import ScopeBlockedError, assert_url_in_scope


class BrowserUnavailableError(RuntimeError):
    pass


@dataclass(slots=True)
class BrowserObservation:
    pages_rendered: set[str] = field(default_factory=set)
    network_requests: int = 0
    security_observations: list[BrowserSecurityObservation] = field(default_factory=list)
    websockets: set[str] = field(default_factory=set)


def request_parameters(
    url: str,
    post_data: str | None,
    content_type: str | None,
) -> tuple[str, ...]:
    names = set(parameter_names(url))
    if not post_data:
        return tuple(sorted(names))

    content_type = (content_type or "").lower()

    if "application/json" in content_type:
        try:
            data = json.loads(post_data)
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, dict):
            names.update(str(key) for key in data)

    elif "application/x-www-form-urlencoded" in content_type:
        names.update(
            key
            for key, _ in parse_qsl(post_data, keep_blank_values=True)
        )

    return tuple(sorted(names))


def browser_source(
    kind: str,
    auth_context: AuthContext | None = None,
) -> str:
    if auth_context is None:
        return f"browser:{kind}"
    return f"browser:{auth_context.name}:{kind}"


def _same_target_host(candidate: str, target: str) -> bool:
    a = urlparse(candidate)
    b = urlparse(target)
    return (
        a.hostname == b.hostname
        and (a.port or (443 if a.scheme == "wss" else 80))
        == (b.port or (443 if b.scheme == "https" else 80))
    )


def merge_rendered_surface(
    crawl: CrawlResult,
    *,
    page_url: str,
    links: list[str],
    scripts: list[str],
    forms: list[dict],
    auth_context: AuthContext | None = None,
) -> None:
    link_source = browser_source("link", auth_context)
    form_source = browser_source("form", auth_context)

    for link in links:
        if same_origin(link, crawl.target):
            crawl.links.add(link)
            params = parameter_names(link)
            crawl.parameters.update(params)
            if params:
                crawl.endpoints.add(
                    EndpointCandidate(
                        url=link,
                        method="GET",
                        source=link_source,
                        parameters=params,
                    )
                )

    for script in scripts:
        if script and same_origin(script, crawl.target):
            crawl.js_assets.add(script)

    for form in forms:
        action = str(form.get("action") or page_url)
        method = str(form.get("method") or "GET").upper()
        parameters = tuple(
            sorted(
                {
                    str(name)
                    for name in form.get("parameters", [])
                    if name
                }
            )
        )

        if not same_origin(action, crawl.target):
            continue

        crawl.forms.append(
            {
                "page": page_url,
                "action": action,
                "method": method,
            }
        )
        crawl.endpoints.add(
            EndpointCandidate(
                url=action,
                method=method,
                source=form_source,
                parameters=parameters,
            )
        )
        crawl.parameters.update(parameters)


class BrowserCrawler:
    def __init__(
        self,
        *,
        max_pages: int = 20,
        navigation_timeout_ms: int = 8_000,
        settle_ms: int = 350,
    ) -> None:
        self.max_pages = max_pages
        self.navigation_timeout_ms = navigation_timeout_ms
        self.settle_ms = settle_ms

    async def enrich(
        self,
        crawl: CrawlResult,
        *,
        auth_context: AuthContext | None = None,
    ) -> BrowserObservation:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise BrowserUnavailableError(
                "Browser mode needs Playwright. Install with "
                "pip install -e '.[browser]' and then run "
                "'playwright install chromium'."
            ) from exc

        observation = BrowserObservation()
        context_name = auth_context.name if auth_context else "anonymous"

        candidates: list[str] = [crawl.target]
        candidates.extend(
            page.url
            for page in crawl.pages
            if "text/html" in page.content_type
        )
        candidates.extend(
            link
            for link in sorted(crawl.links)
            if same_origin(link, crawl.target)
        )

        unique_candidates = list(dict.fromkeys(candidates))[: self.max_pages]

        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(headless=True)
            except Exception as exc:
                raise BrowserUnavailableError(
                    "Chromium is not available for Playwright. Run "
                    "'playwright install chromium'."
                ) from exc

            context_kwargs: dict = {
                "ignore_https_errors": True,
                "service_workers": "block",
            }
            if auth_context and auth_context.headers:
                context_kwargs["extra_http_headers"] = auth_context.headers

            context = await browser.new_context(**context_kwargs)

            if auth_context and auth_context.cookies:
                await context.add_cookies(
                    [
                        {
                            "name": name,
                            "value": value,
                            "url": crawl.target,
                        }
                        for name, value in auth_context.cookies.items()
                    ]
                )

            async def route_handler(route):
                request_url = route.request.url
                try:
                    assert_url_in_scope(request_url, crawl=crawl)
                except RuntimeError:
                    # Standalone browser enrich without bound ScanContext.
                    if not same_origin(request_url, crawl.target):
                        await route.abort()
                        return
                except ScopeBlockedError:
                    await route.abort()
                    return
                if same_origin(request_url, crawl.target):
                    await route.continue_()
                else:
                    await route.abort()

            await context.route("**/*", route_handler)

            page = await context.new_page()
            page.set_default_navigation_timeout(self.navigation_timeout_ms)
            network_source = browser_source("network", auth_context)

            def on_request(request) -> None:
                if request.resource_type not in {"fetch", "xhr"}:
                    return
                if not same_origin(request.url, crawl.target):
                    return

                observation.network_requests += 1
                headers = request.headers
                params = request_parameters(
                    request.url,
                    request.post_data,
                    headers.get("content-type"),
                )
                post_data = request.post_data or ""
                source = network_source
                if "graphql" in request.url.lower() or '"query"' in post_data:
                    source = browser_source("graphql", auth_context)
                crawl.endpoints.add(
                    EndpointCandidate(
                        url=request.url,
                        method=request.method.upper(),
                        source=source,
                        parameters=params,
                    )
                )
                crawl.parameters.update(params)

            def on_websocket(websocket) -> None:
                if _same_target_host(websocket.url, crawl.target):
                    observation.websockets.add(websocket.url)

            page.on("request", on_request)
            page.on("websocket", on_websocket)

            visited: set[str] = set()
            queue = list(unique_candidates)

            while queue and len(visited) < self.max_pages:
                url = queue.pop(0)
                if url in visited or not same_origin(url, crawl.target):
                    continue
                visited.add(url)

                try:
                    assert_url_in_scope(url, crawl=crawl)
                    await page.goto(
                        url,
                        wait_until="domcontentloaded",
                    )
                    await page.wait_for_timeout(self.settle_ms)
                except ScopeBlockedError:
                    continue
                except Exception:
                    continue

                final_url = page.url
                if not same_origin(final_url, crawl.target):
                    continue

                observation.pages_rendered.add(final_url)

                try:
                    surface = await page.evaluate(
                        """() => ({
                            links: Array.from(document.querySelectorAll('a[href]'))
                                .map(a => a.href),
                            scripts: Array.from(document.querySelectorAll('script[src]'))
                                .map(s => s.src),
                            forms: Array.from(document.forms).map(form => ({
                                action: form.action || location.href,
                                method: (form.method || 'GET').toUpperCase(),
                                parameters: Array.from(form.elements)
                                    .map(el => el.name)
                                    .filter(Boolean)
                            })),
                            localKeys: Object.keys(window.localStorage || {}),
                            sessionKeys: Object.keys(window.sessionStorage || {}),
                            frames: Array.from(document.querySelectorAll('iframe[src],frame[src]'))
                                .map(f => f.src)
                                .filter(Boolean),
                            sameDocumentRoutes: Array.from(document.querySelectorAll('a[href^="#/"], a[href^="/"]'))
                                .map(a => a.getAttribute('href'))
                                .filter(Boolean)
                        })"""
                    )
                except Exception:
                    continue

                links = list(surface.get("links", []))
                from urllib.parse import urljoin as _urljoin

                for route in surface.get("sameDocumentRoutes", []):
                    if isinstance(route, str) and route.startswith("/") and not route.startswith("//"):
                        links.append(_urljoin(crawl.target, route))

                for frame_src in surface.get("frames", []):
                    if isinstance(frame_src, str) and same_origin(frame_src, crawl.target):
                        links.append(frame_src)
                        if len(visited) + len(queue) < self.max_pages:
                            queue.append(frame_src)

                merge_rendered_surface(
                    crawl,
                    page_url=final_url,
                    links=links,
                    scripts=list(surface.get("scripts", [])),
                    forms=list(surface.get("forms", [])),
                    auth_context=auth_context,
                )

                # Safe non-mutating SPA navigation: click same-origin anchors only.
                try:
                    safe_hrefs = await page.eval_on_selector_all(
                        "a[href]",
                        """els => els
                            .map(a => ({href: a.href, target: a.target, download: a.hasAttribute('download')}))
                            .filter(item => item.href && !item.download && (!item.target || item.target === '' || item.target === '_self'))
                            .map(item => item.href)
                            .slice(0, 5)""",
                    )
                    for href in safe_hrefs or []:
                        if (
                            same_origin(href, crawl.target)
                            and href not in visited
                            and href not in queue
                            and len(visited) + len(queue) < self.max_pages
                        ):
                            queue.append(href)
                except Exception:
                    pass

                observation.security_observations.extend(
                    storage_observations_from_keys(
                        page_url=final_url,
                        context_name=context_name,
                        local_keys=list(surface.get("localKeys", [])),
                        session_keys=list(surface.get("sessionKeys", [])),
                    )
                )

                for link in links:
                    if (
                        same_origin(link, crawl.target)
                        and link not in visited
                        and link not in queue
                        and len(visited) + len(queue) < self.max_pages
                    ):
                        queue.append(link)

            await context.close()
            await browser.close()

        return observation
