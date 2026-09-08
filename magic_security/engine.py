from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from magic_security.active import run_safe_active_checks
from magic_security.checks import DEFAULT_CHECKS
from magic_security.crawler import HttpCrawler
from magic_security.models import CrawlResult, Finding, Severity
from magic_security.openapi import discover_openapi_endpoints
from magic_security.probes import probe_common_exposures, probe_source_maps


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _is_local_target(target: str) -> bool:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname
    if not host:
        return False
    if host == "localhost":
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False

    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_loopback:
                return False
        except ValueError:
            return False
    return bool(addresses)


class ScannerEngine:
    def __init__(self, max_pages: int = 100) -> None:
        self.crawler = HttpCrawler(max_pages=max_pages)

    async def scan(
        self,
        target: str,
        *,
        active: bool = False,
        allow_remote: bool = False,
    ) -> tuple[CrawlResult, list[Finding]]:
        if not allow_remote and not _is_local_target(target):
            raise ValueError(
                "Remote targets are disabled in the local MVP. Scan localhost/loopback only."
            )

        crawl = await self.crawler.crawl(target)

        openapi_endpoints = await discover_openapi_endpoints(crawl.target)
        crawl.endpoints.update(openapi_endpoints)
        for endpoint in openapi_endpoints:
            crawl.parameters.update(endpoint.parameters)

        findings: list[Finding] = []

        for page in crawl.pages:
            for check in DEFAULT_CHECKS:
                findings.extend(check.run(page))

        findings.extend(await probe_common_exposures(crawl.target))
        findings.extend(await probe_source_maps(crawl.source_maps))

        if active:
            findings.extend(
                await run_safe_active_checks(
                    page_urls=(page.url for page in crawl.pages),
                    endpoints=crawl.endpoints,
                )
            )

        findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.title, f.url))
        return crawl, findings
