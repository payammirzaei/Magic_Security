from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from magic_security.models import CrawlResult, Finding


def build_report(crawl: CrawlResult, findings: list[Finding]) -> dict:
    coverage = (
        asdict(crawl.auth_security_coverage)
        if crawl.auth_security_coverage is not None
        else None
    )

    return {
        "target": crawl.target,
        "attack_surface": {
            "pages": len(crawl.pages),
            "links": len(crawl.links),
            "forms": len(crawl.forms),
            "js_assets": len(crawl.js_assets),
            "endpoints": (
                len(crawl.normalized_endpoints)
                if crawl.normalized_endpoints
                else len(crawl.endpoints)
            ),
            "raw_endpoints": len(crawl.endpoints),
            "normalized_endpoints": len(crawl.normalized_endpoints),
            "classified_endpoints": len(crawl.endpoint_observations),
            "auth_compared_endpoints": len(crawl.auth_comparisons),
            "ownership_signals": len(crawl.ownership_observations),
            "idor_pairwise_tests": len(crawl.pairwise_idor_observations),
            "csrf_candidates": len(crawl.csrf_candidates),
            "session_cookie_observations": len(
                crawl.session_cookie_observations
            ),
            "parameters": len(crawl.parameters),
            "source_maps": len(crawl.source_maps),
            "browser_pages": len(crawl.browser_pages),
            "browser_network_requests": crawl.browser_network_requests,
            "authenticated_browser_contexts": len(
                crawl.authenticated_browser_pages
            ),
            "authenticated_browser_network_requests": sum(
                crawl.authenticated_browser_network_requests.values()
            ),
            "response_fingerprint_groups": len(crawl.response_groups),
        },
        "auth_security": {
            "coverage": coverage,
            "ownership": [
                {
                    "context": item.context,
                    "parameter": item.parameter,
                    "discovered_values": item.discovered_values,
                    "source_endpoints": list(item.source_endpoints),
                }
                for item in crawl.ownership_observations
            ],
            "pairwise_idor": [
                {
                    "endpoint": item.endpoint,
                    "parameter": item.parameter,
                    "parameter_location": item.parameter_location,
                    "owner_context": item.owner_context,
                    "requester_context": item.requester_context,
                    "owner_status": item.owner_status,
                    "requester_status": item.requester_status,
                    "cross_account_verified": item.cross_account_verified,
                }
                for item in crawl.pairwise_idor_observations
            ],
            "session_cookies": [
                {
                    "context": item.context,
                    "source_url": item.source_url,
                    "cookie_name": item.cookie_name,
                    "auth_like": item.auth_like,
                    "secure": item.secure,
                    "httponly": item.httponly,
                    "same_site": item.same_site,
                }
                for item in crawl.session_cookie_observations
            ],
            "csrf_posture": [
                {
                    "url": item.url,
                    "method": item.method,
                    "parameters": list(item.parameters),
                    "auth_style": item.auth_style,
                    "token_signal_present": item.token_signal_present,
                    "posture": item.posture,
                }
                for item in crawl.csrf_candidates
            ],
        },
        "browser_pages": sorted(crawl.browser_pages),
        "authenticated_browser": [
            {
                "context": context,
                "pages": sorted(
                    crawl.authenticated_browser_pages.get(context, set())
                ),
                "network_requests": (
                    crawl.authenticated_browser_network_requests.get(
                        context,
                        0,
                    )
                ),
            }
            for context in sorted(crawl.authenticated_browser_pages)
        ],
        "response_groups": [
            {
                "fingerprint": fingerprint,
                "urls": list(urls),
                "count": len(urls),
            }
            for fingerprint, urls in sorted(crawl.response_groups.items())
        ],
        "normalized_endpoints": [
            {
                "url": endpoint.url,
                "method": endpoint.method,
                "parameters": list(endpoint.parameters),
                "sources": list(endpoint.sources),
            }
            for endpoint in crawl.normalized_endpoints
        ],
        "endpoint_observations": [
            {
                "url": item.url,
                "method": item.method,
                "status_code": item.status_code,
                "classification": item.classification,
                "content_type": item.content_type,
                "sensitive_fields": list(item.sensitive_fields),
                "secret_fields": list(item.secret_fields),
            }
            for item in crawl.endpoint_observations
        ],
        "auth_comparisons": [
            {
                "url": item.url,
                "method": item.method,
                "boundary": item.boundary,
                "anonymous_status": item.anonymous_status,
                "context_statuses": [
                    {"context": name, "status_code": status}
                    for name, status in item.context_statuses
                ],
                "authenticated_responses_differ": (
                    item.authenticated_responses_differ
                ),
            }
            for item in crawl.auth_comparisons
        ],
        "raw_endpoints": [
            {
                "url": endpoint.url,
                "method": endpoint.method,
                "source": endpoint.source,
                "parameters": list(endpoint.parameters),
            }
            for endpoint in sorted(
                crawl.endpoints,
                key=lambda item: (item.url, item.method, item.source),
            )
        ],
        "findings": [
            {
                **asdict(finding),
                "severity": finding.severity.value,
                "kind": finding.kind.value,
                "affected_urls": list(finding.affected_urls),
                "verified": finding.verified,
            }
            for finding in findings
        ],
    }


def write_json_report(
    path: str | Path,
    crawl: CrawlResult,
    findings: list[Finding],
) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build_report(crawl, findings), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination
