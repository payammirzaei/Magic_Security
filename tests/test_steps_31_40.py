"""Tests for STEPs 31–40 workflows, history, and policy."""

from __future__ import annotations

import json

import httpx
import pytest

from magic_security.backtesting import (
    build_scan_snapshot,
    load_snapshot,
)
from magic_security.history import HistoryStore
from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.policy import RegressionPolicy, evaluate_policy
from magic_security.version import SNAPSHOT_SCHEMA_VERSION
from magic_security.workflow_runner import WorkflowRunner
from magic_security.workflow_schema import (
    WorkflowSchemaError,
    parse_workflow_dict,
    validate_workflows_for_run,
)


def test_workflow_schema_rejects_unsafe_before_network(tmp_path):
    bad = {
        "name": "evil",
        "safety": "disposable_mutate",
        "steps": [
            {
                "id": "create",
                "phase": "create",
                "method": "POST",
                "path": "/api/notes",
                "creates_resource": True,
                "body": "<?php system('id'); ?>",
            }
        ],
    }
    with pytest.raises(WorkflowSchemaError):
        parse_workflow_dict(bad)


def test_workflow_schema_requires_cleanup_for_mutate():
    with pytest.raises(WorkflowSchemaError, match="cleanup"):
        parse_workflow_dict(
            {
                "name": "no_cleanup",
                "safety": "disposable_mutate",
                "steps": [
                    {
                        "id": "create",
                        "phase": "create",
                        "method": "POST",
                        "path": "/api/x",
                        "creates_resource": True,
                    }
                ],
            }
        )


@pytest.mark.asyncio
async def test_workflow_runner_create_read_delete(monkeypatch):
    store: dict[str, dict] = {}

    async def fake_request(self, method, url, **kwargs):
        request = httpx.Request(method, url)
        if method == "POST" and url.endswith("/api/notes"):
            store["1"] = {"id": "1", "body": "x"}
            return httpx.Response(
                201,
                request=request,
                json={"id": "1"},
            )
        if method == "GET" and "/api/notes/" in url:
            return httpx.Response(
                200,
                request=request,
                json=store.get("1", {}),
            )
        if method == "DELETE" and "/api/notes/" in url:
            store.pop("1", None)
            return httpx.Response(200, request=request, json={})
        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
    workflow = parse_workflow_dict(
        {
            "name": "crud",
            "safety": "disposable_mutate",
            "requires_disposable": True,
            "steps": [
                {
                    "id": "create",
                    "phase": "create",
                    "method": "POST",
                    "path": "/api/notes",
                    "context": "user_a",
                    "creates_resource": True,
                    "body": {"title": "t"},
                    "extract": [
                        {"name": "resource_id", "from": "json", "path": "id"}
                    ],
                    "assert": [{"type": "status", "value": 201}],
                },
                {
                    "id": "read",
                    "phase": "read",
                    "method": "GET",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_a",
                    "assert": [{"type": "status", "value": 200}],
                },
                {
                    "id": "cleanup",
                    "phase": "cleanup",
                    "method": "DELETE",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_a",
                    "cleanup_of": "create",
                    "assert": [{"type": "status", "value": 200}],
                },
            ],
        }
    )
    contexts = {
        "user_a": AuthContext(
            name="user_a",
            cookies={"demo_session": "A"},
            disposable=True,
        )
    }
    runner = WorkflowRunner(
        target="http://127.0.0.1/",
        contexts=contexts,
    )
    record = await runner.run(workflow)
    assert record.ok
    assert store == {}
    assert runner.tracker.all_cleaned()
    dumped = record.to_dict()
    assert "demo_session" not in json.dumps(dumped)


def test_validate_requires_disposable_contexts():
    workflow = parse_workflow_dict(
        {
            "name": "m",
            "safety": "disposable_mutate",
            "steps": [
                {
                    "id": "c",
                    "phase": "create",
                    "method": "POST",
                    "path": "/api/notes",
                    "context": "user_a",
                    "creates_resource": True,
                },
                {
                    "id": "d",
                    "phase": "cleanup",
                    "method": "DELETE",
                    "path": "/api/notes/1",
                    "context": "user_a",
                },
            ],
        }
    )
    with pytest.raises(WorkflowSchemaError):
        validate_workflows_for_run(
            [workflow],
            auth_enabled=True,
            browser_enabled=False,
            disposable_contexts=[],
        )


def test_snapshot_v1_loads_and_migrates(tmp_path):
    path = tmp_path / "v1.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "created_at": "2026-01-01T00:00:00+00:00",
                "scanner_version": "1.1.0",
                "target": "http://127.0.0.1/",
                "modes": {"http": True},
                "attack_surface": {
                    "fingerprint": "abc",
                    "items": [],
                    "counts": {},
                },
                "coverage": [],
                "findings": [],
                "history": {
                    "known_fingerprints": [],
                    "resolved_fingerprints": [],
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_snapshot(path)
    assert loaded["schema_version"] == SNAPSHOT_SCHEMA_VERSION
    assert "evidence_fingerprints" in loaded
    assert "scan_profile" in loaded


def test_snapshot_v2_build_contains_new_fields():
    crawl = CrawlResult(target="http://127.0.0.1/")
    findings = [
        Finding(
            title="x",
            severity=Severity.HIGH,
            kind=FindingKind.VULNERABILITY,
            url="http://127.0.0.1/",
            description="d",
            evidence="e",
            remediation="r",
            confidence=1.0,
            check_id="t",
            fingerprint="fp1",
        )
    ]
    snap = build_scan_snapshot(
        crawl,
        findings,
        modes={"http": True, "active": True},
        commit="abc",
    )
    assert snap["schema_version"] == 2
    assert snap["metadata"]["commit"] == "abc"
    assert snap["evidence_fingerprints"]
    assert all(isinstance(item, str) for item in snap["evidence_fingerprints"])


def test_history_store_roundtrip(tmp_path):
    store = HistoryStore(root=tmp_path / ".magic-security")
    target = "http://127.0.0.1:8000/"
    store.add_target(target)
    snap = {
        "schema_version": 2,
        "target": target,
        "findings": [],
        "modes": {},
        "coverage": [],
        "attack_surface": {"fingerprint": "x", "items": [], "counts": {}},
        "history": {"known_fingerprints": [], "resolved_fingerprints": []},
    }
    path = store.save_scan(target, snap)
    assert path.exists()
    baseline = store.set_baseline(target, path)
    assert baseline.exists()
    assert store.list_scans(target)
    assert store.get_baseline(target) is not None


def test_policy_fails_on_new_verified_high_not_unchanged_debt():
    diff = {
        "new": [
            {
                "title": "New BOLA",
                "severity": "high",
                "verified": True,
                "confidence": 1.0,
                "fingerprint": "new1",
            }
        ],
        "unchanged": [
            {
                "title": "Old missing header",
                "severity": "low",
                "verified": True,
                "fingerprint": "old1",
            }
        ],
        "reintroduced": [],
        "worsened": [],
        "summary": {},
    }
    result = evaluate_policy(diff, policy=RegressionPolicy())
    assert result.passed is False
    assert result.exit_code == 1
    assert any("New BOLA" in item for item in result.failures)

    clean = {
        "new": [],
        "unchanged": diff["unchanged"],
        "reintroduced": [],
        "worsened": [],
        "summary": {},
    }
    ok = evaluate_policy(clean, policy=RegressionPolicy())
    assert ok.passed is True
    assert ok.exit_code == 0


def test_unsupported_snapshot_schema_errors(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps({"schema_version": 99, "findings": []}),
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="Unsupported snapshot schema"):
        load_snapshot(path)
