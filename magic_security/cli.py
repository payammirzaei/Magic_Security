from __future__ import annotations

import argparse
import asyncio
from collections import Counter

from magic_security.auth import AuthConfigError, load_auth_contexts
from magic_security.browser import BrowserUnavailableError
from magic_security.engine import ScannerEngine
from magic_security.models import FindingKind
from magic_security.reporting import write_json_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="magic-security",
        description="Local-first evidence-driven web security scanner.",
    )
    parser.add_argument(
        "target",
        help="Local target URL, e.g. http://localhost:3000",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=100,
        help="Maximum same-origin pages to crawl",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help=(
            "Use Playwright for anonymous/authenticated runtime discovery "
            "and browser XSS verification"
        ),
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help=(
            "Run non-destructive external verification checks "
            "(injection, GraphQL, CORS, redirects, rate behavior)"
        ),
    )
    parser.add_argument(
        "--auth-contexts",
        help=(
            "Local JSON file with two or more test-user contexts; "
            "enables authorization/session security checks"
        ),
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Write the complete scan report to a JSON file",
    )
    return parser


async def _run(
    target: str,
    max_pages: int,
    browser: bool,
    active: bool,
    auth_context_path: str | None,
    json_path: str | None,
) -> int:
    engine = ScannerEngine(max_pages=max_pages)

    try:
        auth_contexts = (
            load_auth_contexts(auth_context_path)
            if auth_context_path
            else None
        )
        crawl, findings = await engine.scan(
            target,
            browser=browser,
            active=active,
            auth_contexts=auth_contexts,
        )
    except (
        ValueError,
        BrowserUnavailableError,
        AuthConfigError,
    ) as exc:
        print(f"Error: {exc}")
        return 2

    modes = ["http"]
    if browser:
        modes.append("browser")
    if active:
        modes.append("external-verification")
    if auth_contexts:
        modes.append("auth-security-suite")

    print(f"\nTarget: {crawl.target}")
    print(f"Mode:   {' + '.join(modes)}")

    print("\nAttack Surface")
    print("--------------")
    print(f"Pages:                 {len(crawl.pages)}")
    print(f"Links:                 {len(crawl.links)}")
    print(f"Forms:                 {len(crawl.forms)}")
    print(f"JS assets:             {len(crawl.js_assets)}")
    print(f"Raw endpoints:         {len(crawl.endpoints)}")
    print(f"Normalized endpoints:  {len(crawl.normalized_endpoints)}")
    print(f"Parameters:            {len(crawl.parameters)}")
    print(f"Source maps:           {len(crawl.source_maps)}")

    if browser:
        print(f"Browser pages:         {len(crawl.browser_pages)}")
        print(f"Browser API reqs:      {crawl.browser_network_requests}")

    if browser and auth_contexts:
        for context in sorted(
            crawl.authenticated_browser_pages
        ):
            pages = len(
                crawl.authenticated_browser_pages[context]
            )
            requests = (
                crawl.authenticated_browser_network_requests.get(
                    context,
                    0,
                )
            )
            print(
                f"Auth browser {context}: "
                f"pages={pages}, api_reqs={requests}"
            )

    if active and crawl.endpoint_observations:
        counts = Counter(
            item.classification
            for item in crawl.endpoint_observations
        )
        summary = ", ".join(
            f"{key}={value}"
            for key, value in sorted(counts.items())
        )
        print(f"Endpoint classes:      {summary}")

    auth_coverage = crawl.auth_security_coverage
    if auth_coverage is not None:
        print("\nAuth Security Coverage")
        print("----------------------")
        print(
            f"Auth compared:         "
            f"{auth_coverage.auth_compared_endpoints}"
        )
        print(
            f"Protected endpoints:   "
            f"{auth_coverage.protected_endpoints}"
        )
        print(
            f"User-specific:         "
            f"{auth_coverage.user_specific_endpoints}"
        )
        print(
            f"Ownership signals:     "
            f"{auth_coverage.ownership_signals}"
        )
        print(
            f"IDOR pairwise tests:   "
            f"{auth_coverage.idor_pairwise_tests}"
        )
        print(
            f"Verified IDOR/BOLA:    "
            f"{auth_coverage.idor_verified}"
        )
        print(
            f"State-changing APIs:   "
            f"{auth_coverage.state_changing_endpoints}"
        )
        print(
            f"CSRF needs verify:     "
            f"{auth_coverage.csrf_needs_verification}"
        )
        print(
            f"Weak session cookies:  "
            f"{auth_coverage.weak_session_cookie_observations}"
        )

    browser_cov = crawl.browser_security_coverage
    if browser_cov is not None:
        print("\nBrowser Security Coverage")
        print("-------------------------")
        print(
            f"Artifacts scanned:        "
            f"{browser_cov.artifacts_scanned}"
        )
        print(
            f"DOM source/sink:          "
            f"{browser_cov.dom_source_sink_candidates}"
        )
        print(
            f"DOM XSS verified:         "
            f"{browser_cov.dom_xss_verified}"
        )
        print(
            f"Message handlers:         "
            f"{browser_cov.message_handlers}"
        )
        print(
            f"Missing origin signal:    "
            f"{browser_cov.message_handlers_missing_origin}"
        )
        print(
            f"Client redirects:         "
            f"{browser_cov.client_redirect_candidates}"
        )
        print(
            f"Sensitive storage keys:   "
            f"{browser_cov.sensitive_storage_keys}"
        )
        print(
            f"WebSocket endpoints:      "
            f"{browser_cov.websocket_endpoints}"
        )

    ext = crawl.external_security_coverage
    if ext is not None:
        print("\nExternal Security Coverage")
        print("--------------------------")
        print(
            f"Injection observations:  "
            f"{ext.injection_tests}"
        )
        print(
            f"HTML injection verified: "
            f"{ext.html_injection_verified}"
        )
        print(
            f"XSS execution verified:  "
            f"{ext.xss_execution_verified}"
        )
        print(
            f"GraphQL tested:           "
            f"{ext.graphql_endpoints_tested}"
        )
        print(
            f"GraphQL introspection:    "
            f"{ext.graphql_introspection_exposed}"
        )
        print(
            f"Client artifacts scanned: "
            f"{ext.client_artifacts_scanned}"
        )
        print(
            f"Secret-like artifacts:    "
            f"{ext.secret_like_artifacts}"
        )
        print(
            f"Protected CORS exposed:   "
            f"{ext.protected_cors_exposed}"
        )
        print(
            f"Risky shared cache:       "
            f"{ext.risky_shared_cache}"
        )
        print(
            f"Rate-limit endpoints:     "
            f"{ext.rate_limit_endpoints_tested}"
        )
        print(
            f"Observed throttling:      "
            f"{ext.rate_limit_throttled}"
        )
        print(
            f"Parameter security tests: "
            f"{ext.parameter_security_tests}"
        )
        print(
            f"DB error triggers:        "
            f"{ext.database_error_triggers}"
        )
        print(
            f"SSTI verified:            "
            f"{ext.ssti_verified}"
        )
        print(
            f"CRLF verified:            "
            f"{ext.crlf_verified}"
        )
        print(
            f"Protocol observations:    "
            f"{ext.protocol_observations}"
        )

    if crawl.coverage_registry:
        statuses = Counter(
            item["status"] for item in crawl.coverage_registry
        )
        print("\n42-Category Coverage")
        print("--------------------")
        for status, count in sorted(statuses.items()):
            print(f"{status:22} {count}")

    groups = (
        (
            FindingKind.VULNERABILITY,
            "Vulnerabilities",
        ),
        (
            FindingKind.EXPOSURE,
            "Exposures",
        ),
        (
            FindingKind.HARDENING,
            "Hardening",
        ),
    )

    for kind, heading in groups:
        items = [
            finding
            for finding in findings
            if finding.kind is kind
        ]
        print(f"\n{heading}")
        print("-" * len(heading))

        if not items:
            print("None")
            continue

        for finding in items:
            verified = (
                "VERIFIED"
                if finding.verified
                else (
                    f"confidence "
                    f"{finding.confidence:.0%}"
                )
            )
            affected_count = (
                len(finding.affected_urls) or 1
            )
            suffix = (
                f", {affected_count} affected URLs"
                if affected_count > 1
                else ""
            )

            print(
                f"[{finding.severity.value.upper()}] "
                f"{finding.title} "
                f"({verified}{suffix})"
            )
            print(f"  URL: {finding.url}")
            print(
                f"  Evidence: {finding.evidence}"
            )
            print(f"  Fix: {finding.remediation}")

            if finding.fingerprint:
                print(
                    f"  Fingerprint: "
                    f"{finding.fingerprint}"
                )

            if finding.cwe or finding.owasp:
                refs = " | ".join(
                    value
                    for value in (
                        finding.cwe,
                        finding.owasp,
                    )
                    if value
                )
                print(f"  Ref: {refs}")

    if json_path:
        destination = write_json_report(
            json_path,
            crawl,
            findings,
        )
        print(f"\nJSON report: {destination}")

    return 0


def main() -> None:
    args = _parser().parse_args()
    raise SystemExit(
        asyncio.run(
            _run(
                args.target,
                args.max_pages,
                args.browser,
                args.active,
                args.auth_contexts,
                args.json_path,
            )
        )
    )
