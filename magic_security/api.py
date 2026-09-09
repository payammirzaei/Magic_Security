"""Local FastAPI control plane (STEP 48). Optional dependency: fastapi/uvicorn."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from magic_security.backtesting import build_scan_snapshot, diff_snapshots
from magic_security.engine import ScannerEngine
from magic_security.history import target_id_for
from magic_security.persistence import Persistence
from magic_security.reporting import build_report
from magic_security.target_registry import TargetRegistry


def create_app(db_path: str | Path = ".magic-security/magic.db"):
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel, Field
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Install magic-security[api] (fastapi/uvicorn) to use the local API"
        ) from exc

    app = FastAPI(title="Magic Security Local API", version="1.0")
    persistence = Persistence(Path(db_path))
    persistence.init_schema()
    registry = TargetRegistry()

    class TargetIn(BaseModel):
        base_url: str
        environment: str = "local"
        trusted_local: bool = True

    class ScanIn(BaseModel):
        target: str
        browser: bool = False
        active: bool = False
        auth_contexts_path: str | None = None
        max_pages: int = 50

    @app.post("/targets")
    def post_target(body: TargetIn) -> dict[str, Any]:
        item = registry.register(
            body.base_url,
            environment=body.environment,
            trusted_local=body.trusted_local,
        )
        persistence.upsert_target(
            item.target_id,
            item.base_url,
            environment=item.environment,
            metadata=item.to_dict(),
        )
        return item.to_dict()

    @app.get("/targets")
    def get_targets() -> list[dict[str, Any]]:
        return persistence.list_targets()

    @app.post("/scans")
    async def post_scan(body: ScanIn) -> dict[str, Any]:
        from magic_security.auth import load_auth_contexts
        from magic_security.config import scan_config_from_flags

        try:
            auth = (
                load_auth_contexts(body.auth_contexts_path)
                if body.auth_contexts_path
                else None
            )
            config = scan_config_from_flags(
                target=body.target,
                max_pages=body.max_pages,
                browser=body.browser,
                active=body.active,
                auth_contexts=auth,
            )
            crawl, findings = await ScannerEngine(
                max_pages=body.max_pages
            ).scan(config=config)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        report = build_report(
            crawl,
            findings,
            modes={
                "browser": body.browser,
                "active": body.active,
                "auth_contexts": len(auth or []),
            },
        )
        snapshot = build_scan_snapshot(
            crawl,
            findings,
            modes=report["modes"],
        )
        tid = target_id_for(body.target)
        persistence.upsert_target(tid, body.target)
        scan_id = persistence.save_scan(
            target_id=tid,
            report=report,
            snapshot=snapshot,
        )
        return {"id": scan_id, "target_id": tid, "summary": report["summary"]}

    @app.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return row

    @app.get("/scans/{scan_id}/findings")
    def get_findings(scan_id: str) -> list[dict[str, Any]]:
        if persistence.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return persistence.get_findings(scan_id)

    @app.get("/scans/{scan_id}/coverage")
    def get_coverage(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return (row.get("report") or {}).get("coverage") or {}

    @app.get("/scans/{scan_id}/diff")
    def get_diff(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        baseline = persistence.get_baseline(row["target_id"])
        if baseline is None:
            raise HTTPException(status_code=404, detail="baseline missing")
        return diff_snapshots(baseline, row.get("snapshot") or {})

    return app
