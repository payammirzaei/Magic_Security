from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from magic_security import __version__
from magic_security.fingerprints import (
    deduplicate_findings,
    normalize_finding_url,
)
from magic_security.models import CrawlResult, Finding, Severity


SNAPSHOT_SCHEMA_VERSION = 1

_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class SnapshotError(ValueError):
    pass


def _surface_endpoint_key(method: str, url: str, parameters: list[str] | tuple[str, ...]) -> str:
    normalized = normalize_finding_url(url)
    params = ",".join(sorted(parameters))
    return f"endpoint:{method.upper()}:{normalized}:{params}"


def _surface_items(crawl: CrawlResult) -> list[str]:
    items: set[str] = set()

    for endpoint in crawl.normalized_endpoints:
        items.add(
            _surface_endpoint_key(
                endpoint.method,
                endpoint.url,
                endpoint.parameters,
            )
        )

    for url in crawl.js_assets:
        items.add(f"javascript:{normalize_finding_url(url)}")
    for url in crawl.source_maps:
        items.add(f"sourcemap:{normalize_finding_url(url)}")
    for url in crawl.websocket_endpoints:
        items.add(f"websocket:{normalize_finding_url(url)}")

    return sorted(items)


def _coverage_state(crawl: CrawlResult) -> list[dict[str, str]]:
    return sorted(
        (
            {
                "category": item.get("category", ""),
                "status": item.get("status", ""),
            }
            for item in crawl.coverage_registry
        ),
        key=lambda item: item["category"],
    )


def _finding_record(finding: Finding) -> dict[str, Any]:
    if not finding.fingerprint or not finding.check_id:
        finding = deduplicate_findings([finding])[0]

    return {
        "fingerprint": finding.fingerprint,
        "check_id": finding.check_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "kind": finding.kind.value,
        "confidence": finding.confidence,
        "confidence_level": finding.confidence_level.value,
        "verified": finding.verified,
        "url": finding.url,
        "affected_urls": sorted(finding.affected_urls or (finding.url,)),
        "occurrences": finding.occurrences,
    }


def build_scan_snapshot(
    crawl: CrawlResult,
    findings: list[Finding],
    *,
    modes: dict[str, Any] | None = None,
    created_at: str | None = None,
    scanner_version: str | None = None,
) -> dict[str, Any]:
    normalized_findings = deduplicate_findings(findings)
    surface_items = _surface_items(crawl)
    surface_hash = hashlib.sha256(
        "\n".join(surface_items).encode("utf-8")
    ).hexdigest()[:20]

    timestamp = created_at or datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "created_at": timestamp,
        "scanner_version": scanner_version or __version__,
        "target": crawl.target,
        "modes": modes or {},
        "attack_surface": {
            "fingerprint": surface_hash,
            "items": surface_items,
            "counts": {
                "pages": len(crawl.pages),
                "links": len(crawl.links),
                "forms": len(crawl.forms),
                "js_assets": len(crawl.js_assets),
                "normalized_endpoints": len(crawl.normalized_endpoints),
                "source_maps": len(crawl.source_maps),
                "websocket_endpoints": len(crawl.websocket_endpoints),
            },
        },
        "coverage": _coverage_state(crawl),
        "findings": sorted(
            (_finding_record(item) for item in normalized_findings),
            key=lambda item: (item["fingerprint"], item["title"]),
        ),
        "history": {
            "known_fingerprints": [],
            "resolved_fingerprints": [],
        },
    }


def write_snapshot(path: str | Path, snapshot: dict[str, Any]) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination


def load_snapshot(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"Cannot load snapshot {source}: {exc}") from exc

    if data.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotError(
            f"Unsupported snapshot schema: {data.get('schema_version')!r}"
        )
    if not isinstance(data.get("findings"), list):
        raise SnapshotError("Snapshot is missing a valid findings list.")
    return data


def _coverage_map(snapshot: dict[str, Any]) -> dict[str, str]:
    return {
        item["category"]: item["status"]
        for item in snapshot.get("coverage", [])
        if item.get("category")
    }


def _finding_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["fingerprint"]: item
        for item in snapshot.get("findings", [])
        if item.get("fingerprint")
    }


def _severity_rank(value: str) -> int:
    return _SEVERITY_RANK.get(value, -1)


def diff_snapshots(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    if baseline.get("target") != current.get("target"):
        raise SnapshotError(
            "Baseline and current snapshot targets do not match: "
            f"{baseline.get('target')!r} != {current.get('target')!r}"
        )

    before = _finding_map(baseline)
    after = _finding_map(current)
    previously_resolved = set(
        baseline.get("history", {}).get("resolved_fingerprints", [])
    )

    new_items: list[dict[str, Any]] = []
    reintroduced: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    worsened: list[dict[str, Any]] = []
    improved: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []

    for fingerprint in sorted(after.keys() - before.keys()):
        item = after[fingerprint]
        if fingerprint in previously_resolved:
            reintroduced.append(item)
        else:
            new_items.append(item)

    for fingerprint in sorted(before.keys() - after.keys()):
        resolved.append(before[fingerprint])

    for fingerprint in sorted(before.keys() & after.keys()):
        old = before[fingerprint]
        new = after[fingerprint]
        old_urls = set(old.get("affected_urls", []))
        new_urls = set(new.get("affected_urls", []))

        became_verified = bool(new.get("verified")) and not bool(old.get("verified"))
        severity_up = _severity_rank(new.get("severity", "")) > _severity_rank(
            old.get("severity", "")
        )
        severity_down = _severity_rank(new.get("severity", "")) < _severity_rank(
            old.get("severity", "")
        )

        if severity_up or became_verified or (new_urls - old_urls):
            worsened.append(
                {
                    "before": old,
                    "after": new,
                    "added_affected_urls": sorted(new_urls - old_urls),
                }
            )
        elif severity_down or (old_urls - new_urls):
            improved.append(
                {
                    "before": old,
                    "after": new,
                    "removed_affected_urls": sorted(old_urls - new_urls),
                }
            )
        else:
            unchanged.append(new)

    before_surface = set(
        baseline.get("attack_surface", {}).get("items", [])
    )
    after_surface = set(
        current.get("attack_surface", {}).get("items", [])
    )

    before_coverage = _coverage_map(baseline)
    after_coverage = _coverage_map(current)
    coverage_categories = sorted(
        set(before_coverage) | set(after_coverage)
    )
    coverage_changes = [
        {
            "category": category,
            "before": before_coverage.get(category),
            "after": after_coverage.get(category),
        }
        for category in coverage_categories
        if before_coverage.get(category) != after_coverage.get(category)
    ]

    result = {
        "target": current.get("target"),
        "baseline_created_at": baseline.get("created_at"),
        "current_created_at": current.get("created_at"),
        "summary": {
            "new": len(new_items),
            "reintroduced": len(reintroduced),
            "resolved": len(resolved),
            "worsened": len(worsened),
            "improved": len(improved),
            "unchanged": len(unchanged),
            "surface_added": len(after_surface - before_surface),
            "surface_removed": len(before_surface - after_surface),
            "coverage_changed": len(coverage_changes),
        },
        "findings": {
            "new": new_items,
            "reintroduced": reintroduced,
            "resolved": resolved,
            "worsened": worsened,
            "improved": improved,
            "unchanged": unchanged,
        },
        "attack_surface": {
            "added": sorted(after_surface - before_surface),
            "removed": sorted(before_surface - after_surface),
        },
        "coverage": {
            "equivalent": not coverage_changes
            and baseline.get("modes", {}) == current.get("modes", {}),
            "changes": coverage_changes,
            "baseline_modes": baseline.get("modes", {}),
            "current_modes": current.get("modes", {}),
        },
    }
    return result


def apply_history(
    baseline: dict[str, Any],
    current: dict[str, Any],
    diff: dict[str, Any],
) -> dict[str, Any]:
    known = set(
        baseline.get("history", {}).get("known_fingerprints", [])
    )
    known.update(_finding_map(baseline))
    resolved = set(
        baseline.get("history", {}).get("resolved_fingerprints", [])
    )
    resolved.update(
        item["fingerprint"]
        for item in diff.get("findings", {}).get("resolved", [])
    )

    current_fingerprints = set(_finding_map(current))
    known.update(current_fingerprints)
    resolved.difference_update(current_fingerprints)

    current["history"] = {
        "known_fingerprints": sorted(known),
        "resolved_fingerprints": sorted(resolved),
    }
    return current
