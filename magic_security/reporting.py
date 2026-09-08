from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from magic_security.models import CrawlResult, Finding


def build_report(crawl: CrawlResult, findings: list[Finding]) -> dict:
    auth_coverage = (
        asdict(crawl.auth_security_coverage)
        if crawl.auth_security_coverage is not None
        else None
    )
    external_coverage = (
        asdict(crawl.external_security_coverage)
        if crawl.external_security_coverage is not None
        else None
    )
    browser_coverage = (
        asdict(crawl.browser_security_coverage)
        if crawl.browser_security_coverage is not None
        else None
    )
    server_coverage = (
        asdict(crawl.server_security_coverage)
        if crawl.server_security_coverage is not None
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
            "injection_observations": len(crawl.injection_observations),
            "graphql_observations": len(crawl.graphql_observations),
            "client_artifacts_scanned": len(
                crawl.client_artifact_observations
            ),
            "browser_security_observations": len(
                crawl.browser_security_observations
            ),
            "server_security_observations": len(
                crawl.server_security_observations
            ),
            "websocket_endpoints": len(crawl.websocket_endpoints),
            "protected_cors_observations": len(
                crawl.cors_impact_observations
            ),
            "cache_observations": len(crawl.cache_observations),
            "rate_limit_observations": len(
                crawl.rate_limit_observations
            ),
            "parameter_security_observations": len(
                crawl.parameter_security_observations
            ),
            "protocol_security_observations": len(
                crawl.protocol_security_observations
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
        "coverage": {
            "auth_security": auth_coverage,
            "external_security": external_coverage,
            "browser_security": browser_coverage,
            "categories": crawl.coverage_registry,
        },
        "browser_security": {
            "websockets": sorted(crawl.websocket_endpoints),
            "observations": [
                asdict(item)
                for item in crawl.browser_security_observations
            ],
        },
        "auth_security": {
            "ownership": [
                asdict(item)
                for item in crawl.ownership_observations
            ],
            "pairwise_idor": [
                asdict(item)
                for item in crawl.pairwise_idor_observations
            ],
            "session_cookies": [
                asdict(item)
                for item in crawl.session_cookie_observations
            ],
            "csrf_posture": [
                {
                    **asdict(item),
                    "parameters": list(item.parameters),
                }
                for item in crawl.csrf_candidates
            ],
        },
        "external_security": {
            "injection": [
                asdict(item)
                for item in crawl.injection_observations
            ],
            "graphql": [
                asdict(item)
                for item in crawl.graphql_observations
            ],
            "client_artifacts": [
                {
                    **asdict(item),
                    "secret_like_names": list(item.secret_like_names),
                    "token_shapes": list(item.token_shapes),
                }
                for item in crawl.client_artifact_observations
            ],
            "protected_cors": [
                asdict(item)
                for item in crawl.cors_impact_observations
            ],
            "authenticated_cache": [
                asdict(item)
                for item in crawl.cache_observations
            ],
            "rate_limits": [
                {
                    **asdict(item),
                    "statuses": list(item.statuses),
                    "rate_limit_headers": list(
                        item.rate_limit_headers
                    ),
                }
                for item in crawl.rate_limit_observations
            ],
            "parameter_security": [
                asdict(item)
                for item in crawl.parameter_security_observations
            ],
            "protocol_security": [
                asdict(item)
                for item in crawl.protocol_security_observations
            ],
        },
        "browser_pages": sorted(crawl.browser_pages),
        "authenticated_browser": [
            {
                "context": context,
                "pages": sorted(
                    crawl.authenticated_browser_pages.get(
                        context,
                        set(),
                    )
                ),
                "network_requests": (
                    crawl.authenticated_browser_network_requests.get(
                        context,
                        0,
                    )
                ),
            }
            for context in sorted(
                crawl.authenticated_browser_pages
            )
        ],
        "response_groups": [
            {
                "fingerprint": fingerprint,
                "urls": list(urls),
                "count": len(urls),
            }
            for fingerprint, urls in sorted(
                crawl.response_groups.items()
            )
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
                    {
                        "context": name,
                        "status_code": status,
                    }
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
                key=lambda item: (
                    item.url,
                    item.method,
                    item.source,
                ),
            )
        ],
        "findings": [
            {
                **asdict(finding),
                "severity": finding.severity.value,
                "kind": finding.kind.value,
                "affected_urls": list(
                    finding.affected_urls
                ),
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
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    destination.write_text(
        json.dumps(
            build_report(crawl, findings),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return destination
