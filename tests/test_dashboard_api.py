"""API dashboard control-plane tests."""

from __future__ import annotations

from pathlib import Path

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

    health = client.get("/api/health")
    assert health.status_code == 200

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

    html = client.get(f"/api/scans/{scan_id}/report.html")
    assert html.status_code == 200
    assert "Magic Security" in html.text or "Demo finding" in html.text

    targets = client.post(
        "/api/targets",
        json={"base_url": "http://127.0.0.1:8000/", "trusted_local": True},
    )
    assert targets.status_code == 200
    assert client.get("/api/targets").status_code == 200
