"""Browser Security Verification Pack v2 (STEP 22).

Consolidates browser/client verification under one pack API with an explicit
candidate vs verified split. Does not rewrite underlying checkers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from magic_security.browser_security import (
    analyze_browser_artifacts,
    build_browser_security_coverage,
    storage_findings,
    verify_dom_xss_browser,
)
from magic_security.evidence import EvidenceObject, attach_evidence, evidence_from_finding
from magic_security.injection import (
    verify_reflected_html_injection,
    verify_reflected_xss_browser,
)
from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    FindingKind,
    NormalizedEndpoint,
)


@dataclass
class BrowserPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    candidate_count: int = 0
    verified_count: int = 0


def _tag_candidate_or_verified(finding: Finding) -> Finding:
    evidence = evidence_from_finding(finding)
    if finding.verified:
        if evidence.confidence != "verified":
            evidence.confidence = "verified"
            attach_evidence(finding, evidence)
        return finding

    # Static / heuristic browser signals remain candidates unless proven.
    if evidence.confidence == "verified":
        evidence.confidence = "candidate"
    if not finding.check_id:
        finding.check_id = "browser.candidate"
    if "candidate" not in (finding.check_id or ""):
        if finding.confidence < 0.95 and not finding.check_id.endswith(
            ".candidate"
        ):
            finding.check_id = f"{finding.check_id}.candidate"
    attach_evidence(finding, evidence)
    return finding


async def run_browser_pack(
    crawl: CrawlResult,
    *,
    active: bool = False,
    browser: bool = False,
    auth_contexts: list[AuthContext] | None = None,
    endpoints: list[NormalizedEndpoint] | None = None,
) -> BrowserPackResult:
    result = BrowserPackResult()
    exercised: list[str] = []
    skipped: list[str] = []
    findings: list[Finding] = []

    (
        browser_static_observations,
        static_websockets,
        browser_static_findings,
    ) = await analyze_browser_artifacts(
        crawl.js_assets,
        crawl.source_maps,
    )
    crawl.browser_security_observations.extend(browser_static_observations)
    crawl.websocket_endpoints.update(static_websockets)
    findings.extend(browser_static_findings)
    exercised.append("static_artifacts")

    normalized = endpoints or crawl.normalized_endpoints

    if active and browser:
        (
            xss_observations,
            xss_findings,
        ) = await verify_reflected_xss_browser(normalized)
        crawl.injection_observations.extend(xss_observations)
        findings.extend(xss_findings)
        exercised.append("reflected_xss_browser")
        xss_urls = {
            item.url
            for item in xss_observations
            if item.script_execution_verified
        }

        html_candidates = [
            endpoint for endpoint in normalized if endpoint.url not in xss_urls
        ]
        (
            html_observations,
            html_findings,
        ) = await verify_reflected_html_injection(html_candidates)
        crawl.injection_observations.extend(html_observations)
        findings.extend(html_findings)
        exercised.append("html_injection")

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
        crawl.browser_security_observations.extend(dom_observations)
        findings.extend(dom_findings)
        exercised.append("dom_xss")
    else:
        if not active:
            skipped.extend(
                ["reflected_xss_browser", "html_injection", "dom_xss"]
            )
        elif not browser:
            skipped.extend(
                ["reflected_xss_browser", "html_injection", "dom_xss"]
            )

    findings.extend(storage_findings(crawl.browser_security_observations))
    exercised.append("storage")

    tagged: list[Finding] = []
    for finding in findings:
        tagged.append(_tag_candidate_or_verified(finding))

    result.findings = tagged
    result.candidate_count = sum(1 for f in tagged if not f.verified)
    result.verified_count = sum(1 for f in tagged if f.verified)
    crawl.browser_security_coverage = build_browser_security_coverage(
        crawl.browser_security_observations,
        crawl.websocket_endpoints,
        artifacts_scanned=len(crawl.js_assets) + len(crawl.source_maps),
    )
    result.coverage = {
        "pack": "browser_v2",
        "exercised": exercised,
        "skipped": skipped,
        "candidate_findings": result.candidate_count,
        "verified_findings": result.verified_count,
    }
    return result
