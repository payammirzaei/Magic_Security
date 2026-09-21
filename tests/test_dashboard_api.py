"""API dashboard control-plane tests."""

from __future__ import annotations

from pathlib import Path
import time

import pytest

from magic_security.persistence import Persistence


def test_persistence_list_and_baseline(tmp_path: Path):
    store = Persistence(tmp_path / "magic.db")
    store.init_schema()
    store.upsert_target("t1", "http://127.0.0.1:8000/")
    scan_id = store.create_scan(target_id="t1", status="queued")
    store.update_scan_status(scan_id, "running")
    store.complete_scan(
        scan_id,
        report={
            "summary": {"findings": 1, "vulnerabilities": 1},
            "scan_validity": {"checks_executed": 2, "status": "complete"},
            "findings": [{"fingerprint": "fp1", "title": "x", "severity": "high"}],
        },
        snapshot={"schema_version": 2, "findings": [], "target": "http://127.0.0.1:8000/"},
        status="completed",
    )
    listed = store.list_scans(target_id="t1")
    assert listed
    assert listed[0]["status"] == "completed"
    assert listed[0]["summary"]["findings"] == 1
    row = store.get_scan(scan_id)
    assert row is not None
    assert row["summary"]["vulnerabilities"] == 1
    store.set_baseline("t1", row["snapshot"])
    assert store.get_baseline("t1") is not None


def test_workspace_scope_hides_targets_and_scans(tmp_path: Path):
    store = Persistence(tmp_path / "scope.db")
    store.init_schema()
    store.upsert_target("default-target", "http://default.test", workspace_id="default")
    store.upsert_target("other-target", "http://other.test", workspace_id="other")
    default_scan = store.create_scan(target_id="default-target", workspace_id="default")
    other_scan = store.create_scan(target_id="other-target", workspace_id="other")
    assert [item["id"] for item in store.list_targets(workspace_id="default")] == ["default-target"]
    assert [item["id"] for item in store.list_scans(workspace_id="other")] == [other_scan]
    assert len(store.list_scans(limit=1, offset=0, workspace_id="default")) == 1
    assert store.get_scan(other_scan)["workspace_id"] == "other"
    assert store.get_scan(default_scan)["workspace_id"] == "default"
    pending = store.list_pending_scans(workspace_id="default")
    assert pending and pending[0]["id"] == default_scan
    assert store.delete_target("default-target", workspace_id="default") is False
    store.update_scan_status(default_scan, "failed")
    assert store.delete_target("default-target", workspace_id="default") is True


def test_api_key_guard_and_workspace_detail_scope(tmp_path: Path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from magic_security.api import create_app

    monkeypatch.setenv("MAGIC_SECURITY_API_KEY", "test-secret")
    app = create_app(tmp_path / "auth.db")
    client = TestClient(app)
    assert client.get("/api/targets").status_code == 401
    headers = {"Authorization": "Bearer test-secret"}
    assert client.get("/api/health").status_code == 200
    created = client.post("/api/targets?workspace_id=alpha", json={"base_url": "https://alpha.test"}, headers=headers)
    assert created.status_code == 200
    assert len(client.get("/api/targets?workspace_id=alpha", headers=headers).json()) == 1
    second = client.post("/api/targets?workspace_id=alpha", json={"base_url": "https://beta.test"}, headers=headers)
    assert second.status_code == 200
    assert len(client.get("/api/targets?workspace_id=alpha&limit=1&offset=0", headers=headers).json()) == 1
    assert len(client.get("/api/targets?workspace_id=alpha&limit=1&offset=1", headers=headers).json()) == 1
    assert client.get("/api/targets?workspace_id=beta", headers=headers).json() == []

    target_id = created.json()["target_id"]
    deleted = client.delete(f"/api/targets/{target_id}?workspace_id=alpha", headers=headers)
    assert deleted.status_code == 200
    remaining = client.get("/api/targets?workspace_id=alpha", headers=headers).json()
    assert len(remaining) == 1
    assert remaining[0]["base_url"] == "https://beta.test"
    assert client.delete(f"/api/targets/{target_id}?workspace_id=beta", headers=headers).status_code == 404
    workspace = client.post("/api/workspaces", json={"name": "Security Team EU"}, headers=headers)
    assert workspace.status_code == 200
    assert workspace.json()["id"] == "security-team-eu"
    assert client.post("/api/workspaces", json={"name": "Security Team EU"}, headers=headers).status_code == 409
    assert client.get("/api/targets?workspace_id=security-team-eu", headers=headers).json() == []
    me = client.get("/api/me?workspace_id=security-team-eu", headers=headers)
    assert me.status_code == 200
    assert me.json()["workspace"]["id"] == "security-team-eu"
    assert client.get("/api/me?workspace_id=missing", headers=headers).status_code == 404
    renamed = client.patch("/api/workspaces/security-team-eu", json={"name": "EU Security"}, headers=headers)
    assert renamed.status_code == 200
    assert renamed.json()["id"] == "security-team-eu"
    assert renamed.json()["name"] == "EU Security"
    assert client.patch("/api/workspaces/missing", json={"name": "Nope"}, headers=headers).status_code == 404


def test_api_async_scan_list_baseline_html(tmp_path: Path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from magic_security import api as api_mod
    from magic_security.models import CrawlResult, Finding, FindingKind, Severity

    async def fake_scan(self, config=None, **kwargs):  # noqa: ANN001
        crawl = CrawlResult(target="http://127.0.0.1:9/")
        crawl.check_coverage = [{"check_id": "demo", "status": "executed"}]
        crawl.pages = []  # type: ignore[assignment]
        findings = [
            Finding(
                title="Demo finding",
                severity=Severity.HIGH,
                kind=FindingKind.VULNERABILITY,
                url="http://127.0.0.1:9/",
                description="d",
                evidence="e",
                remediation="r",
                confidence=1.0,
            )
        ]
        return crawl, findings

    monkeypatch.setattr(
        "magic_security.engine.ScannerEngine.scan",
        fake_scan,
    )

    app = api_mod.create_app(tmp_path / "api.db")
    client = TestClient(app)
    client.__enter__()

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["service"] == "magic-security-api"
    assert health.json()["version"] == "1.3.0"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["referrer-policy"] == "no-referrer"
    assert health.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
    assert "default-src 'self'" in health.headers["content-security-policy"]
    assert health.headers["x-request-id"]
    assert health.headers["server-timing"].startswith("app;dur=")
    traced = client.get("/api/health", headers={"X-Request-ID": "trace-test-123"})
    assert traced.headers["x-request-id"] == "trace-test-123"
    assert health.json()["status"] in {"ok", "degraded"}
    assert "workers" in health.json()

    created = client.post(
        "/api/scans",
        json={"target": "http://127.0.0.1:9/", "max_pages": 1, "active": False},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "queued"
    scan_id = body["id"]

    # Background task runs within TestClient
    detail = client.get(f"/api/scans/{scan_id}")
    for _ in range(20):
        if detail.json().get("status") in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.05)
        detail = client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "completed"
    assert detail.json()["summary"]["findings"] >= 1

    listed = client.get("/api/scans")
    assert listed.status_code == 200
    assert any(item["id"] == scan_id for item in listed.json())

    baseline = client.post(f"/api/scans/{scan_id}/baseline")
    assert baseline.status_code == 200

    diff = client.get(f"/api/scans/{scan_id}/diff")
    assert diff.status_code == 200
    assert client.get(f"/api/scans/{scan_id}/coverage?workspace_id=other").status_code == 404
    assert client.get(f"/api/scans/{scan_id}/diff?workspace_id=other").status_code == 404
    assert client.post(f"/api/scans/{scan_id}/baseline?workspace_id=other").status_code == 404

    html = client.get(f"/api/scans/{scan_id}/report.html")
    assert html.status_code == 200
    assert "Magic Security" in html.text or "Demo finding" in html.text
    assert html.headers["cache-control"] == "no-store"
    report_json = client.get(f"/api/scans/{scan_id}/report.json")
    assert report_json.status_code == 200
    assert report_json.headers["content-disposition"].startswith("attachment;")
    assert report_json.headers["cache-control"] == "no-store"
    assert report_json.json()["summary"]["findings"] >= 1
    assert client.get(f"/api/scans/{scan_id}/report.json?workspace_id=other").status_code == 404
    assert client.post(f"/api/scans/{scan_id}/cancel").status_code == 409
    assert client.post(f"/api/scans/{scan_id}/cancel?workspace_id=other").status_code == 404

    targets = client.post(
        "/api/targets",
        json={"base_url": "http://127.0.0.1:8000/", "trusted_local": True},
    )
    assert targets.status_code == 200
    assert client.get("/api/targets").status_code == 200
