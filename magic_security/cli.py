from __future__ import annotations

import argparse
import asyncio

from magic_security.engine import ScannerEngine
from magic_security.models import FindingKind


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="magic-security",
        description="Local-first evidence-driven web security scanner.",
    )
    parser.add_argument("target", help="Local target URL, e.g. http://localhost:3000")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum same-origin pages to crawl")
    return parser


async def _run(target: str, max_pages: int) -> int:
    engine = ScannerEngine(max_pages=max_pages)

    try:
        crawl, findings = await engine.scan(target)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    print(f"\nTarget: {crawl.target}")
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
        for endpoint in sorted(crawl.endpoints, key=lambda item: (item.url, item.method, item.source)):
            params = f" params={','.join(endpoint.parameters)}" if endpoint.parameters else ""
            print(f"{endpoint.method:7} {endpoint.url} [{endpoint.source}]{params}")

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
            verified = "VERIFIED" if finding.verified else f"confidence {finding.confidence:.0%}"
            print(f"[{finding.severity.value.upper()}] {finding.title} ({verified})")
            print(f"  URL: {finding.url}")
            print(f"  Evidence: {finding.evidence}")
            print(f"  Fix: {finding.remediation}")

    return 0


def main() -> None:
    args = _parser().parse_args()
    raise SystemExit(asyncio.run(_run(args.target, args.max_pages)))
