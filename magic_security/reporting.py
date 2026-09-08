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
            "endpoints": len(crawl.endpoints),
            "parameters": len(crawl.parameters),
            "source_maps": len(crawl.source_maps),
        },
        "endpoints": [
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
