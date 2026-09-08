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
    parser.add_argument("target", help="Local target URL, e.g. http://localhost:3000")
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
            "Use Playwright for anonymous runtime discovery and, when auth contexts "
            "are supplied, authenticated runtime discovery for each test context"
        ),
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Run endpoint classification and non-destructive verification checks",
    )
    parser.add_argument(
        "--auth-contexts",
        help=(
            "Local JSON file containing at least two test-user header/cookie contexts; "
            "enables auth-boundary and read-only IDOR/BOLA verification"
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
    except (ValueError, BrowserUnavailableError, AuthConfigError) as exc:
        print(f"Error: {exc}")
        return 2

    modes = ["http"]
    if browser:
        modes.append("browser")
    if active:
        modes.append("safe-active")
    if auth_contexts:
        modes.append("authz-read-only")
        if browser:
            modes.append("authenticated-browser")

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
    print(f"Response groups:       {len(crawl.response_groups)}")

    if browser:
        print(f"Browser pages:         {len(crawl.browser_pages)}")
        print(f"Browser API reqs:      {crawl.browser_network_requests}")

    if browser and auth_contexts:
        for context in sorted(crawl.authenticated_browser_pages):
            pages = len(crawl.authenticated_browser_pages[context])
            requests = crawl.authenticated_browser_network_requests.get(
                context,
                0,
            )
            print(
                f"Auth browser {context}: "
                f"pages={pages}, api_reqs={requests}"
            )

    if active and crawl.endpoint_observations:
        counts = Counter(
            item.classification for item in crawl.endpoint_observations
        )
        summary = ", ".join(
            f"{key}={value}" for key, value in sorted(counts.items())
        )
        print(f"Endpoint classes:      {summary}")

    if auth_contexts and crawl.auth_comparisons:
        counts = Counter(item.boundary for item in crawl.auth_comparisons)
        summary = ", ".join(
            f"{key}={value}" for key, value in sorted(counts.items())
        )
        print(f"Auth boundaries:       {summary}")

        differing = sum(
            1
            for item in crawl.auth_comparisons
            if item.authenticated_responses_differ
        )
        print(f"User-specific replies: {differing}")

    if auth_contexts:
        verified_idor = sum(
            1
            for item in crawl.idor_observations
            if item.cross_account_verified
        )
        print(
            f"IDOR templates:        {len(crawl.idor_observations)} "
            f"(verified: {verified_idor})"
        )

    if crawl.normalized_endpoints:
        print("\nNormalized Endpoints")
        print("--------------------")
        for endpoint in crawl.normalized_endpoints:
            params = (
                f" params={','.join(endpoint.parameters)}"
                if endpoint.parameters
                else ""
            )
            sources = ",".join(endpoint.sources)
            print(
                f"{endpoint.method:7} {endpoint.url} "
                f"[sources={sources}]{params}"
            )

    groups = (
        (FindingKind.VULNERABILITY, "Vulnerabilities"),
        (FindingKind.EXPOSURE, "Exposures"),
        (FindingKind.HARDENING, "Hardening"),
    )

    for kind, heading in groups:
        items = [f for f in findings if f.kind is kind]
        print(f"\n{heading}")
        print("-" * len(heading))
        if not items:
            print("None")
            continue

        for finding in items:
            verified = (
                "VERIFIED"
                if finding.verified
                else f"confidence {finding.confidence:.0%}"
            )
            affected_count = len(finding.affected_urls) or 1
            suffix = (
                f", {affected_count} affected URLs"
                if affected_count > 1
                else ""
            )
            print(
                f"[{finding.severity.value.upper()}] "
                f"{finding.title} ({verified}{suffix})"
            )
            print(f"  URL: {finding.url}")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Fix: {finding.remediation}")
            if finding.fingerprint:
                print(f"  Fingerprint: {finding.fingerprint}")
            if finding.cwe or finding.owasp:
                refs = " | ".join(
                    value for value in (finding.cwe, finding.owasp) if value
                )
                print(f"  Ref: {refs}")

    if json_path:
        destination = write_json_report(json_path, crawl, findings)
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
