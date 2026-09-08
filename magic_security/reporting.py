from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from magic_security.models import CrawlResult, Finding


def build_report(crawl: CrawlResult, findings: list[Finding]) -> dict:
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
            "parameters": len(crawl.parameters),
            "source_maps": len(crawl.source_maps),
            "browser_pages": len(crawl.browser_pages),
            "browser_network_requests": crawl.browser_network_requests,
            "response_fingerprint_groups": len(crawl.response_groups),
        },
        "browser_pages": sorted(crawl.browser_pages),
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
