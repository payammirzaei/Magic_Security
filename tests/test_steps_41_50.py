"""Tests for STEPs 41–50."""

from __future__ import annotations

from pathlib import Path

import pytest

from magic_security.framework_analysis import (
    analyze_repository_tree,
    extract_laravel_routes,
    extract_nextjs_routes,
)
from magic_security.history import HistoryStore
from magic_security.models import CrawlResult, Finding, FindingKind, Severity
from magic_security.persistence import Persistence
from magic_security.profiles import production_safe_remote_profile
from magic_security.reporting import build_report, render_terminal_report
from magic_security.reporting_html import render_html_report, write_html_report
from magic_security.repo_adapter import MockRepositoryAdapter
from magic_security.repo_security import analyze_repo_security
from magic_security.target_registry import (
    AuthorizationState,
    TargetRegistry,
    TargetRegistryError,
)
from magic_security.version import REPORT_SCHEMA_VERSION


def test_report_v2_distinguishes_zero_findings_vs_zero_tests():
    empty = build_report(CrawlResult(target="http://127.0.0.1/"), [])
    assert empty["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert empty["scan_validity"]["checks_executed"] == 0
    assert empty["scan_validity"]["zero_tests_executed"] is True
    text = render_terminal_report(empty)
    assert "0 tests executed" in text

    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.check_coverage = [
        {"check_id": "x", "status": "executed"},
    ]
    crawl.pages = []  # type: ignore[assignment]
    with_tests = build_report(crawl, [])
    assert with_tests["scan_validity"]["checks_executed"] == 1
    assert with_tests["scan_validity"]["zero_tests_executed"] is False
    assert "no_verified_or_candidate_issues_reported" in (
        with_tests["scan_validity"]["zero_findings_means"]
    )


def test_html_report_from_canonical_model(tmp_path):
    crawl = CrawlResult(target="http://127.0.0.1/")
    findings = [
        Finding(
            title="Demo",
            severity=Severity.HIGH,
            kind=FindingKind.VULNERABILITY,
            url="http://127.0.0.1/",
            description="d",
            evidence="e",
            remediation="r",
            confidence=1.0,
        )
    ]
    report = build_report(crawl, findings)
    html = render_html_report(report)
    assert "Magic Security Report" in html
    assert "Demo" in html
    assert "password" not in html.lower() or "evidence" in html.lower()
    path = write_html_report(tmp_path / "r.html", crawl, findings)
    assert path.exists()


def test_unverified_remote_cannot_run_active(tmp_path):
    store = HistoryStore(root=tmp_path / ".magic-security")
    registry = TargetRegistry(store)
    registry.register(
        "https://example.com",
        trusted_local=False,
        environment="production",
    )
    item = registry.get("https://example.com")
    assert item is not None
    assert item.authorization_state is AuthorizationState.UNVERIFIED
    with pytest.raises(TargetRegistryError, match="Unverified"):
        registry.assert_active_allowed(
            "https://example.com",
            active=True,
            allow_remote=True,
        )


def test_production_safe_profile_blocks_mutations():
    config = production_safe_remote_profile(
        "https://app.example.com",
        allowed_hosts=("app.example.com",),
    )
    assert config.allow_remote is True
    assert config.budgets.max_active_mutations == 0
    assert config.workflows_path is None
    assert config.rate.requests_per_second <= 1.0
    assert "/payment" in config.scope.denied_paths


def test_mock_repo_adapter_does_not_verify_runtime():
    snap = MockRepositoryAdapter().load()
    assert snap.framework == "nextjs"
    assert snap.routes
    # Source enrichment never sets verified runtime proof.
    result = analyze_repo_security(
        Path("."),
        adapter=MockRepositoryAdapter(),
    )
    assert all(item.get("verified_runtime") is False for item in result.findings)


def test_nextjs_and_laravel_route_extraction(tmp_path):
    next_root = tmp_path / "nextapp"
    route = next_root / "app" / "api" / "me" / "route.ts"
    route.parent.mkdir(parents=True)
    route.write_text("export async function GET() { return Response.json({}) }", encoding="utf-8")
    (next_root / "next.config.mjs").write_text("export default {}", encoding="utf-8")
    next_routes = extract_nextjs_routes(next_root)
    assert any(item.path == "/api/me" for item in next_routes)
    analysis = analyze_repository_tree(next_root)
    assert analysis["framework"] == "nextjs"

    laravel = tmp_path / "laravel"
    (laravel / "routes").mkdir(parents=True)
    (laravel / "artisan").write_text("#!/usr/bin/env php\n", encoding="utf-8")
    (laravel / "routes" / "api.php").write_text(
        "Route::get('/api/accounts/{id}', [AccountController::class, 'show'])->middleware(['auth']);\n",
        encoding="utf-8",
    )
    laravel_routes = extract_laravel_routes(laravel)
    assert any(item.path == "/api/accounts/{id}" for item in laravel_routes)
    assert any(item.auth_required for item in laravel_routes)


def test_repo_security_secret_fingerprint_only(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "config.py").write_text(
        "API_KEY = 'super-secret-value-should-not-leak'\n",
        encoding="utf-8",
    )
    result = analyze_repo_security(root)
    assert result.findings
    blob = str(result.findings)
    assert "super-secret-value-should-not-leak" not in blob
    assert "value_fingerprint=" in blob


def test_persistence_and_api_entities(tmp_path):
    db = tmp_path / "magic.db"
    store = Persistence(db)
    store.init_schema()
    store.upsert_target("t1", "http://127.0.0.1/", environment="local")
    scan_id = store.save_scan(
        target_id="t1",
        report={
            "summary": {"findings": 1},
            "findings": [
                {
                    "fingerprint": "abc",
                    "title": "x",
                    "severity": "high",
                }
            ],
            "coverage": {"packs": {}},
        },
        snapshot={"schema_version": 2, "findings": [], "target": "http://127.0.0.1/"},
    )
    assert store.get_scan(scan_id) is not None
    assert store.get_findings(scan_id)
    assert store.list_targets()


def test_create_app_optional(tmp_path):
    pytest.importorskip("fastapi")
    from magic_security.api import create_app

    app = create_app(tmp_path / "api.db")
    assert app.title.startswith("Magic Security")


def test_acceptance_scope_and_policy_promises():
    """STEP 50 acceptance slice: scope + policy promises."""
    from magic_security.policy import evaluate_policy
    from magic_security.scope import is_local_target

    assert is_local_target("http://127.0.0.1:8000/")
    assert not is_local_target("https://example.com", resolve_dns=False)
    result = evaluate_policy(
        {
            "new": [
                {
                    "title": "New high",
                    "severity": "high",
                    "verified": True,
                }
            ],
            "unchanged": [{"title": "old low", "severity": "low", "verified": True}],
            "reintroduced": [],
            "worsened": [],
        }
    )
    assert result.exit_code == 1
    assert result.passed is False
