from __future__ import annotations

import argparse
import asyncio

from magic_security.auth import AuthConfigError, load_auth_contexts
from magic_security.backtesting import (
    SnapshotError,
    apply_history,
    build_scan_snapshot,
    diff_snapshots,
    load_snapshot,
    write_snapshot,
)
from magic_security.browser import BrowserUnavailableError
from magic_security.config import scan_config_from_flags
from magic_security.engine import ScannerEngine
from magic_security.models import FindingKind
from magic_security.reporting import build_report, render_terminal_report, write_json_report
from magic_security.reporting_html import write_html_report


def _parser() -> argparse.ArgumentParser:
    from magic_security.version import SCANNER_VERSION

    parser = argparse.ArgumentParser(
        prog="magic-security",
        description="Local-first evidence-driven web security scanner.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {SCANNER_VERSION}",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
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
            "Run non-destructive external/server verification checks "
            "(injection, GraphQL, SSRF callback, traversal, auth bypass, "
            "CORS, redirects, rate behavior)"
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
    parser.add_argument(
        "--snapshot",
        dest="snapshot_path",
        help=(
            "Write a compact security backtesting snapshot. "
            "Snapshots contain stable finding identities, coverage, and attack surface."
        ),
    )
    parser.add_argument(
        "--baseline",
        dest="baseline_path",
        help=(
            "Compare this scan against a previous Magic_Security snapshot "
            "and print security regressions/resolutions."
        ),
    )
    parser.add_argument(
        "--workflows",
        dest="workflows_path",
        help=(
            "JSON/YAML workflow file or directory for disposable "
            "state-changing verification packs"
        ),
    )
    parser.add_argument(
        "--persist-history",
        action="store_true",
        help="Write scan snapshots under .magic-security/targets/<id>/scans",
    )
    parser.add_argument(
        "--fail-on-policy",
        action="store_true",
        help=(
            "Exit non-zero when regression policy fails "
            "(new verified high/critical findings)"
        ),
    )
    parser.add_argument(
        "--html",
        dest="html_path",
        help="Write a standalone HTML security report",
    )
    parser.add_argument(
        "--repo",
        dest="repo_path",
        help="Local repository path for source analysis enrichment",
    )
    return parser


async def _run(
    target: str,
    max_pages: int,
    browser: bool,
    active: bool,
    auth_context_path: str | None,
    json_path: str | None,
    snapshot_path: str | None,
    baseline_path: str | None,
    workflows_path: str | None = None,
    persist_history: bool = False,
    fail_on_policy: bool = False,
    html_path: str | None = None,
    repo_path: str | None = None,
) -> int:
    try:
        auth_contexts = (
            load_auth_contexts(auth_context_path)
            if auth_context_path
            else None
        )
        config = scan_config_from_flags(
            target=target,
            max_pages=max_pages,
            browser=browser,
            active=active,
            auth_contexts=auth_contexts,
            json_path=json_path,
            snapshot_path=snapshot_path,
            baseline_path=baseline_path,
            workflows_path=workflows_path,
            persist_history=persist_history,
            fail_on_policy=fail_on_policy,
            html_path=html_path,
            repo_path=repo_path,
        )
        engine = ScannerEngine(max_pages=config.max_pages)
        crawl, findings = await engine.scan(config=config)
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

    snapshot_modes = {
        "http": True,
        "browser": browser,
        "active": active,
        "auth_contexts": len(auth_contexts or []),
    }
    snapshot = build_scan_snapshot(
        crawl,
        findings,
        modes=snapshot_modes,
    )
    backtest_diff = None
    if baseline_path:
        try:
            baseline = load_snapshot(baseline_path)
            backtest_diff = diff_snapshots(baseline, snapshot)
            snapshot = apply_history(
                baseline,
                snapshot,
                backtest_diff,
            )
        except SnapshotError as exc:
            print(f"Error: {exc}")
            return 2

    from magic_security.policy import evaluate_policy

    policy_result = evaluate_policy(
        backtest_diff,
        snapshot=snapshot,
        pack_failures=len(crawl.pack_failures),
    )
    report = build_report(
        crawl,
        findings,
        modes=snapshot_modes,
        backtest_diff=backtest_diff,
        policy_result=policy_result.to_dict(),
        repository_findings=list(getattr(crawl, "repo_findings", []) or []),
    )
    print(render_terminal_report(report))

    if json_path:
        destination = write_json_report(
            json_path,
            crawl,
            findings,
            modes=snapshot_modes,
            backtest_diff=backtest_diff,
            policy_result=policy_result.to_dict(),
            repository_findings=list(getattr(crawl, "repo_findings", []) or []),
        )
        print(f"\nJSON report: {destination}")

    if html_path:
        destination = write_html_report(
            html_path,
            crawl,
            findings,
            modes=snapshot_modes,
            backtest_diff=backtest_diff,
            policy_result=policy_result.to_dict(),
            repository_findings=list(getattr(crawl, "repo_findings", []) or []),
        )
        print(f"HTML report: {destination}")

    if snapshot_path:
        destination = write_snapshot(
            snapshot_path,
            snapshot,
        )
        print(f"Security snapshot: {destination}")

    if persist_history:
        from magic_security.history import HistoryStore

        store = HistoryStore()
        history_path = store.save_scan(target, snapshot)
        print(f"History scan written to {history_path}")

    if policy_result.failures or policy_result.warnings:
        print("\nRegression Policy")
        print("-----------------")
        for item in policy_result.failures:
            print(f"FAIL: {item}")
        for item in policy_result.warnings:
            print(f"WARN: {item}")

    if fail_on_policy and not policy_result.passed:
        return policy_result.exit_code
    return 0


def main() -> None:
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "checks":
        raise SystemExit(_checks_command(sys.argv[2:]))
    if len(sys.argv) >= 2 and sys.argv[1] in {
        "target",
        "history",
        "baseline",
        "diff",
        "scan",
    }:
        raise SystemExit(_history_command(sys.argv[1], sys.argv[2:]))

    args = _parser().parse_args()
    if not args.target:
        _parser().error("the following arguments are required: target")
    raise SystemExit(
        asyncio.run(
            _run(
                args.target,
                args.max_pages,
                args.browser,
                args.active,
                args.auth_contexts,
                args.json_path,
                args.snapshot_path,
                args.baseline_path,
                workflows_path=args.workflows_path,
                persist_history=args.persist_history,
                fail_on_policy=args.fail_on_policy,
                html_path=args.html_path,
                repo_path=args.repo_path,
            )
        )
    )


def _history_command(command: str, argv: list[str]) -> int:
    from pathlib import Path

    from magic_security.history import HistoryStore
    from magic_security.policy import evaluate_policy
    from magic_security.target_registry import (
        TargetRegistry,
        VerificationMethod,
    )

    store = HistoryStore()
    registry = TargetRegistry(store)

    if command == "target" and argv and argv[0] == "add":
        if len(argv) < 2:
            print("Usage: magic-security target add <url>")
            return 2
        item = registry.register(argv[1], trusted_local=True)
        print(
            f"Target registered id={item.target_id} "
            f"state={item.authorization_state.value}"
        )
        return 0

    if command == "target" and argv and argv[0] == "verify":
        if len(argv) < 2:
            print("Usage: magic-security target verify <url>")
            return 2
        item = registry.mark_verified(
            argv[1],
            method=VerificationMethod.TRUSTED_LOCAL,
        )
        print(f"Target verified: {item.target_id}")
        return 0

    if command == "target" and argv and argv[0] == "list":
        for item in store.list_targets():
            print(f"{item.get('target_id')}\t{item.get('target')}")
        return 0

    if command == "history":
        if not argv:
            print("Usage: magic-security history <url>")
            return 2
        scans = store.list_scans(argv[0])
        if not scans:
            print("No scans found.")
            return 0
        for path in scans:
            print(path)
        return 0

    if command == "baseline" and argv and argv[0] == "set":
        if len(argv) < 3:
            print(
                "Usage: magic-security baseline set <url> <snapshot.json>"
            )
            return 2
        path = store.set_baseline(argv[1], Path(argv[2]))
        print(f"Baseline set at {path}")
        return 0

    if command == "diff":
        if len(argv) < 2:
            print(
                "Usage: magic-security diff <baseline.json> <current.json>"
            )
            return 2
        try:
            baseline = load_snapshot(argv[0])
            current = load_snapshot(argv[1])
            diff = diff_snapshots(baseline, current)
        except SnapshotError as exc:
            print(f"Error: {exc}")
            return 2
        summary = diff["summary"]
        print(
            "new={new} reintroduced={reintroduced} resolved={resolved} "
            "worsened={worsened} unchanged={unchanged}".format(**summary)
        )
        policy = evaluate_policy(diff, snapshot=current)
        if policy.failures:
            for item in policy.failures:
                print(f"FAIL: {item}")
            return policy.exit_code
        return 0

    if command == "scan":
        if not argv:
            print("Usage: magic-security scan <url> [scan flags...]")
            return 2
        args = _parser().parse_args(argv)
        if not args.target:
            args.target = argv[0]
        return asyncio.run(
            _run(
                args.target,
                args.max_pages,
                args.browser,
                args.active,
                args.auth_contexts,
                args.json_path,
                args.snapshot_path,
                args.baseline_path,
                workflows_path=args.workflows_path,
                persist_history=args.persist_history,
                fail_on_policy=args.fail_on_policy,
                html_path=args.html_path,
                repo_path=args.repo_path,
            )
        )

    print(
        "Usage: magic-security "
        "(target add|target verify|target list|history|baseline set|diff|scan)"
    )
    return 2


def _checks_command(argv: list[str]) -> int:
    from magic_security.registry import build_default_registry

    if not argv or argv[0] != "list":
        print("Usage: magic-security checks list")
        return 2

    registry = build_default_registry()
    print("check_id\tpack\tmodes\trisk")
    for item in registry.list_checks():
        modes = ",".join(item.spec.required_modes)
        print(
            f"{item.spec.check_id}\t{item.spec.pack}\t{modes}\t"
            f"{item.spec.risk_class.value}"
        )
    return 0
