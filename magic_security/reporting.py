"""Canonical report model v2 + terminal renderer (STEP 41)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from magic_security.models import CrawlResult, Finding, FindingKind
from magic_security.redaction import Redactor
from magic_security.version import REPORT_SCHEMA_VERSION, SCANNER_VERSION


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "kind": finding.kind.value,
        "url": finding.url,
        "description": finding.description,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "confidence": finding.confidence,
        "confidence_level": finding.confidence_level.value,
        "verified": finding.verified,
        "check_id": finding.check_id,
        "fingerprint": finding.fingerprint,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "affected_urls": list(finding.affected_urls or ()),
        "occurrences": finding.occurrences,
        "structured_evidence": finding.structured_evidence,
        "evidence_source": "runtime",
    }


def build_report(
    crawl: CrawlResult,
    findings: list[Finding],
    *,
    modes: dict[str, Any] | None = None,
    backtest_diff: dict[str, Any] | None = None,
    policy_result: dict[str, Any] | None = None,
    repository_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    checks_executed = sum(
        1
        for row in crawl.check_coverage
        if row.get("status") == "executed"
    )
    checks_failed = len(crawl.pack_failures)
    checks_skipped = sum(
        1
        for row in crawl.check_coverage
        if str(row.get("status", "")).startswith("skipped")
    )
    pack_exercised = {
        name: (block.get("exercised") if isinstance(block, dict) else block)
        for name, block in (crawl.pack_coverage or {}).items()
    }

    verified = [f for f in findings if f.verified]
    exposures = [f for f in findings if f.kind is FindingKind.EXPOSURE]
    hardening = [f for f in findings if f.kind is FindingKind.HARDENING]
    vulnerabilities = [
        f for f in findings if f.kind is FindingKind.VULNERABILITY
    ]

    scan_validity = {
        "status": (
            "partial"
            if checks_failed or (crawl.budget_coverage or {}).get("exhausted")
            else ("complete" if checks_executed or findings or crawl.pages else "empty")
        ),
        "checks_executed": checks_executed,
        "checks_skipped": checks_skipped,
        "checks_failed": checks_failed,
        "pages_crawled": len(crawl.pages),
        "endpoints_normalized": len(crawl.normalized_endpoints),
        "findings_total": len(findings),
        "zero_findings_means": (
            "no_verified_or_candidate_issues_reported"
            if checks_executed > 0
            else "no_tests_executed_or_no_surface"
        ),
        "zero_tests_executed": checks_executed == 0 and not crawl.pages,
    }

    decision = {
        "scan_validity": scan_validity,
        "coverage_equivalence": (
            (backtest_diff or {}).get("coverage", {}).get("equivalent")
            if backtest_diff
            else None
        ),
        "regressions": {
            "new_verified": [
                item
                for item in ((backtest_diff or {}).get("findings", {}) or {}).get(
                    "new", []
                )
                if item.get("verified")
            ],
            "reintroduced": ((backtest_diff or {}).get("findings", {}) or {}).get(
                "reintroduced", []
            ),
            "worsened": ((backtest_diff or {}).get("findings", {}) or {}).get(
                "worsened", []
            ),
            "new_exposures": [
                item
                for item in ((backtest_diff or {}).get("findings", {}) or {}).get(
                    "new", []
                )
                if item.get("kind") == "exposure"
            ],
            "resolved": ((backtest_diff or {}).get("findings", {}) or {}).get(
                "resolved", []
            ),
        },
        "attack_surface_changed": bool(
            ((backtest_diff or {}).get("attack_surface") or {}).get("added")
            or ((backtest_diff or {}).get("attack_surface") or {}).get("removed")
        ),
        "policy": policy_result,
    }

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
    user_side_coverage = (
        asdict(crawl.user_side_security_coverage)
        if crawl.user_side_security_coverage is not None
        else None
    )

    report = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "target": crawl.target,
        "modes": modes or {},
        "reproducibility": {
            "scanner_version": SCANNER_VERSION,
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "modes": modes or {},
            "pack_coverage_keys": sorted(crawl.pack_coverage.keys()),
            "secrets_included": False,
        },
        "decision": decision,
        "scan_validity": scan_validity,
        "summary": {
            "findings": len(findings),
            "vulnerabilities": len(vulnerabilities),
            "exposures": len(exposures),
            "hardening": len(hardening),
            "verified": len(verified),
            "checks_executed": checks_executed,
            "checks_failed": checks_failed,
        },
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
            "robots_entries": crawl.index_robots_entries,
            "sitemap_entries": crawl.index_sitemap_entries,
            "sensitive_endpoint_observations": len(
                crawl.sensitive_endpoint_observations
            ),
            "user_surface_observations": len(
                crawl.user_surface_observations
            ),
        },
        "coverage": {
            "auth_security": auth_coverage,
            "external_security": external_coverage,
            "browser_security": browser_coverage,
            "server_security": server_coverage,
            "user_side_security": user_side_coverage,
            "categories": crawl.coverage_registry,
            "packs": crawl.pack_coverage,
            "pack_exercised": pack_exercised,
            "authz_matrix": crawl.authz_matrix,
            "identity_validation": crawl.identity_validation,
            "checks": crawl.check_coverage,
        },
        "findings": [_finding_dict(item) for item in findings],
        "repository_findings": repository_findings or [],
        "backtest_diff": backtest_diff,
        "attack_surface_graph": crawl.attack_surface_graph,
        "budget_coverage": crawl.budget_coverage,
        "pack_failures": crawl.pack_failures,
        "scan_metrics": crawl.scan_metrics,
    }
    return Redactor().scrub_structure(report)


def render_terminal_report(report: dict[str, Any]) -> str:
    """Decision-focused terminal output from the canonical report."""
    lines: list[str] = []
    validity = report.get("scan_validity") or {}
    summary = report.get("summary") or {}
    decision = report.get("decision") or {}

    lines.append(f"Target: {report.get('target')}")
    lines.append(
        f"Scanner: {report.get('scanner_version')} "
        f"(report schema {report.get('report_schema_version')})"
    )
    lines.append("")
    lines.append("Scan Validity")
    lines.append("-------------")
    lines.append(f"Status:            {validity.get('status')}")
    lines.append(f"Checks executed:   {validity.get('checks_executed')}")
    lines.append(f"Checks skipped:    {validity.get('checks_skipped')}")
    lines.append(f"Checks failed:     {validity.get('checks_failed')}")
    lines.append(f"Pages crawled:     {validity.get('pages_crawled')}")
    lines.append(f"Findings total:    {validity.get('findings_total')}")
    if validity.get("zero_tests_executed"):
        lines.append(
            "NOTE: 0 tests executed — this is NOT the same as 0 findings."
        )
    elif validity.get("findings_total") == 0:
        lines.append(
            "NOTE: 0 findings with tests executed — no issues reported."
        )

    coverage_eq = decision.get("coverage_equivalence")
    if coverage_eq is not None:
        lines.append("")
        lines.append(
            f"Coverage equivalence vs baseline: "
            f"{'yes' if coverage_eq else 'NO'}"
        )

    regressions = decision.get("regressions") or {}
    if any(regressions.values()):
        lines.append("")
        lines.append("Regressions / Diff")
        lines.append("------------------")
        for label, key in (
            ("NEW verified", "new_verified"),
            ("REINTRODUCED", "reintroduced"),
            ("WORSENED", "worsened"),
            ("NEW exposures", "new_exposures"),
            ("RESOLVED", "resolved"),
        ):
            items = regressions.get(key) or []
            if not items:
                continue
            lines.append(f"{label}: {len(items)}")
            for item in items[:8]:
                lines.append(
                    f"  - [{item.get('severity')}] {item.get('title')}"
                )

    lines.append("")
    lines.append("Summary")
    lines.append("-------")
    lines.append(
        f"Vulnerabilities: {summary.get('vulnerabilities')} | "
        f"Exposures: {summary.get('exposures')} | "
        f"Hardening: {summary.get('hardening')} | "
        f"Verified: {summary.get('verified')}"
    )

    findings = report.get("findings") or []
    if findings:
        lines.append("")
        lines.append("Findings")
        lines.append("--------")
        for finding in findings[:40]:
            verified = (
                "VERIFIED" if finding.get("verified") else "candidate"
            )
            lines.append(
                f"[{str(finding.get('severity')).upper()}] "
                f"{finding.get('title')} ({verified})"
            )
            lines.append(f"  URL: {finding.get('url')}")
            lines.append(f"  Evidence: {finding.get('evidence')}")
            lines.append(f"  Fix: {finding.get('remediation')}")

    repo = report.get("repository_findings") or []
    if repo:
        lines.append("")
        lines.append("Source Findings (not runtime proof)")
        lines.append("-----------------------------------")
        for item in repo[:20]:
            lines.append(
                f"[SOURCE:{item.get('severity', 'info')}] "
                f"{item.get('title')} @ {item.get('location')}"
            )

    return "\n".join(lines)


def write_json_report(
    path: str | Path,
    crawl: CrawlResult,
    findings: list[Finding],
    **kwargs: Any,
) -> Path:
    from magic_security.redaction import get_redactor

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    report = build_report(crawl, findings, **kwargs)
    report = get_redactor().scrub_report(report)
    destination.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination
