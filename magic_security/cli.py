from __future__ import annotations

import argparse
import asyncio

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
        "--active",
        action="store_true",
        help="Run the small non-destructive active verification set (localhost only)",
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
    active: bool,
    json_path: str | None,
) -> int:
    engine = ScannerEngine(max_pages=max_pages)

    try:
        crawl, findings = await engine.scan(target, active=active)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    print(f"\nTarget: {crawl.target}")
    print(f"Mode:   {'passive + safe-active verification' if active else 'passive'}")
    print("\nAttack Surface")
    print("--------------")
    print(f"Pages:       {len(crawl.pages)}")
    print(f"Links:       {len(crawl.links)}")
    print(f"Forms:       {len(crawl.forms)}")
    print(f"JS assets:   {len(crawl.js_assets)}")
    print(f"Endpoints:   {len(crawl.endpoints)}")
    print(f"Parameters:  {len(crawl.parameters)}")
    print(f"Source maps: {len(crawl.source_maps)}")

    if crawl.endpoints:
        print("\nDiscovered Endpoints")
        print("--------------------")
        for endpoint in sorted(
            crawl.endpoints,
            key=lambda item: (item.url, item.method, item.source),
        ):
            params = (
                f" params={','.join(endpoint.parameters)}"
                if endpoint.parameters
                else ""
            )
            print(
                f"{endpoint.method:7} {endpoint.url} "
                f"[{endpoint.source}]{params}"
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
            print(
                f"[{finding.severity.value.upper()}] "
                f"{finding.title} ({verified})"
            )
            print(f"  URL: {finding.url}")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Fix: {finding.remediation}")
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
                args.active,
                args.json_path,
            )
        )
    )
