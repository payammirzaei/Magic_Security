from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin
from xml.etree import ElementTree

import httpx

from magic_security.discovery import same_origin
from magic_security.models import EndpointCandidate


@dataclass(frozen=True, slots=True)
class IndexDiscoveryResult:
    links: tuple[str, ...] = ()
    endpoints: tuple[EndpointCandidate, ...] = ()
    robots_entries: int = 0
    sitemap_entries: int = 0


async def discover_index_documents(
    target: str,
    *,
    timeout: float = 5.0,
    max_entries: int = 500,
) -> IndexDiscoveryResult:
    links: set[str] = set()
    endpoints: set[EndpointCandidate] = set()
    robots_entries = 0
    sitemap_entries = 0

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/1.0 index-discovery",
        },
    ) as client:
        robots_url = urljoin(target.rstrip("/") + "/", "robots.txt")
        try:
            response = await client.get(robots_url)
        except httpx.HTTPError:
            response = None

        if (
            response is not None
            and response.status_code == 200
            and "text" in response.headers.get(
                "content-type", "text/plain"
            ).lower()
        ):
            for raw_line in response.text.splitlines():
                line = raw_line.strip()
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key.strip().lower() not in {"allow", "disallow"}:
                    continue
                path = value.strip()
                if not path or path == "/" or "*" in path or "$" in path:
                    continue
                url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                if not same_origin(url, target):
                    continue
                robots_entries += 1
                links.add(url)
                endpoints.add(
                    EndpointCandidate(
                        url=url,
                        method="GET",
                        source="robots",
                    )
                )
                if robots_entries >= max_entries:
                    break

        sitemap_url = urljoin(target.rstrip("/") + "/", "sitemap.xml")
        try:
            response = await client.get(sitemap_url)
        except httpx.HTTPError:
            response = None

        if response is not None and response.status_code == 200:
            try:
                root = ElementTree.fromstring(response.text[:2_000_000])
            except ElementTree.ParseError:
                root = None

            if root is not None:
                for node in root.iter():
                    if not str(node.tag).lower().endswith("loc"):
                        continue
                    value = (node.text or "").strip()
                    if not value:
                        continue
                    url = urljoin(target.rstrip("/") + "/", value)
                    if not same_origin(url, target):
                        continue
                    sitemap_entries += 1
                    links.add(url)
                    endpoints.add(
                        EndpointCandidate(
                            url=url,
                            method="GET",
                            source="sitemap",
                        )
                    )
                    if sitemap_entries >= max_entries:
                        break

    return IndexDiscoveryResult(
        links=tuple(sorted(links)),
        endpoints=tuple(
            sorted(
                endpoints,
                key=lambda item: (item.url, item.method, item.source),
            )
        ),
        robots_entries=robots_entries,
        sitemap_entries=sitemap_entries,
    )
