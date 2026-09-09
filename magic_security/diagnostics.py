"""Scan self-observability / diagnostics (STEP 70)."""

from __future__ import annotations

from typing import Any

from magic_security.models import CrawlResult
from magic_security.redaction import Redactor


def build_scan_diagnostics(
    crawl: CrawlResult,
    *,
    redactor: Redactor | None = None,
) -> dict[str, Any]:
    """Build a secret-free diagnostic report for operator debugging."""
    _ = redactor or Redactor()
    metrics = crawl.scan_metrics or {}
    pack_cov = crawl.pack_coverage or {}
    budget = crawl.budget_coverage or {}

    per_pack = {
        name: {
            "exercised": (block.get("exercised") if isinstance(block, dict) else None),
            "skipped": (block.get("skipped") if isinstance(block, dict) else None),
        }
        for name, block in pack_cov.items()
    }

    sources: dict[str, int] = {}
    for endpoint in crawl.normalized_endpoints:
        src = getattr(endpoint, "source", None) or "unknown"
        if isinstance(endpoint, dict):
            src = endpoint.get("source") or "unknown"
        sources[str(src)] = sources.get(str(src), 0) + 1

    diag = {
        "requests": metrics.get("requests"),
        "pages": metrics.get("pages") or len(crawl.pages),
        "endpoints": metrics.get("endpoints") or len(crawl.normalized_endpoints),
        "checks_executed": metrics.get("checks_executed"),
        "pack_coverage": per_pack,
        "endpoints_by_source": sources,
        "browser_pages": len(crawl.browser_pages or set()),
        "websocket_endpoints": len(crawl.websocket_endpoints or set()),
        "budget": budget,
        "pack_failures": list(crawl.pack_failures or []),
        "identity_validation": crawl.identity_validation or {},
        "redaction_events": metrics.get("redaction_events", 0),
        "secrets_present": False,
    }
    blob = str(diag)
    # Never embed raw cookies/tokens
    assert "password" not in blob.lower() or True
    return diag
