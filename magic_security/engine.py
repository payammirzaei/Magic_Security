from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from magic_security.active import run_safe_active_checks
from magic_security.auth import map_auth_boundaries
from magic_security.behavior_security import (
    analyze_authenticated_cache,
    classify_rate_limits,
    verify_protected_cors,
)
from magic_security.browser import BrowserCrawler
from magic_security.browser_security import (
    analyze_browser_artifacts,
    build_browser_security_coverage,
    storage_findings,
    verify_dom_xss_browser,
)
from magic_security.checks import DEFAULT_CHECKS
from magic_security.classifier import classify_endpoints
from magic_security.client_artifacts import analyze_client_artifacts
from magic_security.coverage import build_auth_security_coverage
from magic_security.coverage_registry import build_coverage_registry
from magic_security.csrf import map_csrf_posture
from magic_security.crawler import HttpCrawler
from magic_security.external_coverage import build_external_security_coverage
from magic_security.fingerprints import (
    deduplicate_findings,
    group_response_fingerprints,
)
from magic_security.graphql_security import analyze_graphql
from magic_security.idor import verify_pairwise_idor_read_access
from magic_security.injection import (
    verify_reflected_html_injection,
    verify_reflected_xss_browser,
)
from magic_security.parameter_security import verify_parameter_security
from magic_security.protocol_security import analyze_protocol_security
from magic_security.models import AuthContext, CrawlResult, Finding, Severity
from magic_security.openapi import discover_openapi_endpoints
from magic_security.probes import probe_common_exposures, probe_source_maps
from magic_security.server_coverage import build_server_security_coverage
from magic_security.server_security import run_server_security_pack
from magic_security.session_security import analyze_session_cookies
from magic_security.surface import normalize_endpoints


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
        browser: bool = False,
        auth_contexts: list[AuthContext] | None = None,
        allow_remote: bool = False,
    ) -> tuple[CrawlResult, list[Finding]]:
        if not allow_remote and not _is_local_target(target):
            raise ValueError(
                "Remote targets are disabled in the local MVP. "
                "Scan localhost/loopback only."
            )

        crawl = await self.crawler.crawl(target)
        crawl.response_groups = group_response_fingerprints(crawl.pages)

        if browser:
            browser_crawler = BrowserCrawler()

            observation = await browser_crawler.enrich(crawl)
            crawl.browser_pages.update(observation.pages_rendered)
            crawl.browser_network_requests += observation.network_requests
            crawl.browser_security_observations.extend(
                observation.security_observations
            )
            crawl.websocket_endpoints.update(observation.websockets)

            if auth_contexts:
                for auth_context in auth_contexts:
                    auth_observation = await browser_crawler.enrich(
                        crawl,
                        auth_context=auth_context,
                    )
                    crawl.authenticated_browser_pages[
                        auth_context.name
                    ] = set(auth_observation.pages_rendered)
                    crawl.authenticated_browser_network_requests[
                        auth_context.name
                    ] = auth_observation.network_requests
                    crawl.browser_security_observations.extend(
                        auth_observation.security_observations
                    )
                    crawl.websocket_endpoints.update(
                        auth_observation.websockets
                    )

        openapi_endpoints = await discover_openapi_endpoints(crawl.target)
        crawl.endpoints.update(openapi_endpoints)
        for endpoint in openapi_endpoints:
            crawl.parameters.update(endpoint.parameters)

        crawl.normalized_endpoints = normalize_endpoints(crawl.endpoints)

        findings: list[Finding] = []

        for page in crawl.pages:
            for check in DEFAULT_CHECKS:
                findings.extend(check.run(page))

        findings.extend(await probe_common_exposures(crawl.target))
        findings.extend(await probe_source_maps(crawl.source_maps))

        (
            crawl.client_artifact_observations,
            artifact_findings,
        ) = await analyze_client_artifacts(
            crawl.js_assets,
            crawl.source_maps,
        )
        findings.extend(artifact_findings)

        (
            browser_static_observations,
            static_websockets,
            browser_static_findings,
        ) = await analyze_browser_artifacts(
            crawl.js_assets,
            crawl.source_maps,
        )
        crawl.browser_security_observations.extend(
            browser_static_observations
        )
        crawl.websocket_endpoints.update(static_websockets)
        findings.extend(browser_static_findings)

        if active:
            observations, classification_findings = await classify_endpoints(
                crawl.normalized_endpoints
            )
            crawl.endpoint_observations = observations
            findings.extend(classification_findings)

            findings.extend(
                await run_safe_active_checks(
                    page_urls=(page.url for page in crawl.pages),
                    endpoints=crawl.endpoints,
                )
            )

            xss_urls: set[str] = set()
            if browser:
                (
                    xss_observations,
                    xss_findings,
                ) = await verify_reflected_xss_browser(
                    crawl.normalized_endpoints
                )
                crawl.injection_observations.extend(xss_observations)
                findings.extend(xss_findings)
                xss_urls = {
                    item.url
                    for item in xss_observations
                    if item.script_execution_verified
                }

            html_candidates = [
                endpoint
                for endpoint in crawl.normalized_endpoints
                if endpoint.url not in xss_urls
            ]
            (
                html_observations,
                html_findings,
            ) = await verify_reflected_html_injection(
                html_candidates
            )
            crawl.injection_observations.extend(html_observations)
            findings.extend(html_findings)

            (
                crawl.graphql_observations,
                graphql_findings,
            ) = await analyze_graphql(crawl.normalized_endpoints)
            findings.extend(graphql_findings)

            crawl.rate_limit_observations = await classify_rate_limits(
                crawl.normalized_endpoints
            )

            (
                crawl.parameter_security_observations,
                parameter_findings,
            ) = await verify_parameter_security(
                crawl.normalized_endpoints
            )
            findings.extend(parameter_findings)

            (
                crawl.protocol_security_observations,
                protocol_findings,
            ) = await analyze_protocol_security(crawl.target)
            findings.extend(protocol_findings)

            (
                crawl.server_security_observations,
                server_findings,
            ) = await run_server_security_pack(
                crawl.normalized_endpoints,
                [
                    page.url
                    for page in crawl.pages
                    if "text/html" in page.content_type
                ],
            )
            findings.extend(server_findings)

            crawl.server_security_coverage = (
                build_server_security_coverage(
                    crawl.parameter_security_observations,
                    crawl.server_security_observations,
                )
            )

            if browser:
                page_urls = [
                    page.url
                    for page in crawl.pages
                    if "text/html" in page.content_type
                ]
                page_urls.extend(sorted(crawl.browser_pages))
                for values in crawl.authenticated_browser_pages.values():
                    page_urls.extend(sorted(values))

                (
                    dom_observations,
                    dom_findings,
                ) = await verify_dom_xss_browser(
                    page_urls,
                    auth_contexts=auth_contexts,
                )
                crawl.browser_security_observations.extend(
                    dom_observations
                )
                findings.extend(dom_findings)

        if auth_contexts:
            crawl.auth_comparisons = await map_auth_boundaries(
                crawl.normalized_endpoints,
                auth_contexts,
            )

            (
                crawl.ownership_observations,
                crawl.pairwise_idor_observations,
                idor_findings,
            ) = await verify_pairwise_idor_read_access(
                crawl.normalized_endpoints,
                auth_contexts,
                auth_comparisons=crawl.auth_comparisons,
            )
            findings.extend(idor_findings)

            (
                crawl.session_cookie_observations,
                session_findings,
            ) = await analyze_session_cookies(
                crawl.normalized_endpoints,
                auth_contexts,
            )
            findings.extend(session_findings)

            crawl.csrf_candidates = map_csrf_posture(
                crawl.normalized_endpoints,
                auth_contexts,
            )

            (
                crawl.cors_impact_observations,
                protected_cors_findings,
            ) = await verify_protected_cors(
                crawl.auth_comparisons,
                auth_contexts,
            )
            findings.extend(protected_cors_findings)

            (
                crawl.cache_observations,
                cache_findings,
            ) = await analyze_authenticated_cache(
                crawl.auth_comparisons,
                auth_contexts,
            )
            findings.extend(cache_findings)

            crawl.auth_security_coverage = build_auth_security_coverage(
                crawl.normalized_endpoints,
                crawl.auth_comparisons,
                crawl.ownership_observations,
                crawl.pairwise_idor_observations,
                crawl.csrf_candidates,
                crawl.session_cookie_observations,
            )

        findings.extend(
            storage_findings(crawl.browser_security_observations)
        )

        crawl.browser_security_coverage = (
            build_browser_security_coverage(
                crawl.browser_security_observations,
                crawl.websocket_endpoints,
                artifacts_scanned=(
                    len(crawl.js_assets)
                    + len(crawl.source_maps)
                ),
            )
        )

        crawl.external_security_coverage = build_external_security_coverage(
            crawl.injection_observations,
            crawl.graphql_observations,
            crawl.client_artifact_observations,
            crawl.cors_impact_observations,
            crawl.cache_observations,
            crawl.rate_limit_observations,
            crawl.parameter_security_observations,
            crawl.protocol_security_observations,
        )

        crawl.coverage_registry = build_coverage_registry(
            crawl,
            active=active,
            browser=browser,
            auth_enabled=bool(auth_contexts),
        )

        findings = deduplicate_findings(findings)
        findings.sort(
            key=lambda f: (
                _SEVERITY_ORDER[f.severity],
                f.title,
                f.url,
            )
        )
        return crawl, findings
