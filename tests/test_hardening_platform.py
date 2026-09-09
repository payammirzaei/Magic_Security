"""STEP 67/69/70 — API safety, dependency inventory, diagnostics."""

from __future__ import annotations

from pathlib import Path

import pytest

from magic_security.dependency_inventory import inventory_dependencies
from magic_security.diagnostics import build_scan_diagnostics
from magic_security.models import CrawlResult


def test_dependency_inventory_reads_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("httpx==0.27.0\n", encoding="utf-8")
    inv = inventory_dependencies(tmp_path)
    assert "requirements.txt" in inv.manifests
    assert any(d.name == "httpx" for d in inv.dependencies)
    assert all(d.to_dict()["vulnerability_status"] == "not_assessed" for d in inv.dependencies)


def test_diagnostics_have_no_secret_seed():
    crawl = CrawlResult(target="http://127.0.0.1:8000/")
    crawl.pack_coverage = {"demo": {"exercised": ["a"], "skipped": []}}
    crawl.scan_metrics = {"requests": 3, "redaction_events": 1}
    diag = build_scan_diagnostics(crawl)
    assert diag["requests"] == 3
    assert "SEED_SECRET" not in str(diag)


def test_api_rejects_path_traversal_repo_style(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from magic_security.api import create_app

    app = create_app(tmp_path / "api.db")
    client = TestClient(app)
    response = client.post(
        "/api/targets",
        json={"base_url": "http://127.0.0.1/", "environment": "../" * 20},
    )
    assert response.status_code in {200, 400, 422}


def test_api_rejects_unsafe_scan_inputs(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from magic_security.api import create_app

    app = create_app(tmp_path / "api2.db")
    client = TestClient(app)
    bad = client.post(
        "/api/scans",
        json={
            "target": "http://127.0.0.1:8000/",
            "auth_contexts_path": "../../etc/passwd",
        },
    )
    assert bad.status_code == 400
    huge = client.post(
        "/api/scans",
        json={"target": "http://127.0.0.1/" + ("a" * 3000)},
    )
    assert huge.status_code == 413
