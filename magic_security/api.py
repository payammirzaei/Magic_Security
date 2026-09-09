"""Local FastAPI control plane — API under /api, SPA from web/dist."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from magic_security.backtesting import build_scan_snapshot, diff_snapshots
from magic_security.engine import ScannerEngine
from magic_security.history import target_id_for
from magic_security.persistence import Persistence
from magic_security.reporting import build_report
from magic_security.reporting_html import render_html_report
from magic_security.target_registry import TargetRegistry

WEB_DIST = Path(__file__).resolve().parent.parent / "web" / "dist"


def create_app(db_path: str | Path = ".magic-security/magic.db"):
    try:
        from fastapi import APIRouter, Body, FastAPI, HTTPException, Query
        from fastapi.responses import FileResponse, HTMLResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Install magic-security[api] (fastapi/uvicorn) to use the local API"
        ) from exc

    app = FastAPI(title="Magic Security Local API", version="1.0")
    api = APIRouter(prefix="/api")
    persistence = Persistence(Path(db_path))
    persistence.init_schema()
    registry = TargetRegistry()

    async def _run_scan_job(scan_id: str, body: dict[str, Any]) -> None:
        from magic_security.auth import load_auth_contexts
        from magic_security.config import scan_config_from_flags

        persistence.update_scan_status(scan_id, "running")
        try:
            auth = (
                load_auth_contexts(body["auth_contexts_path"])
                if body.get("auth_contexts_path")
                else None
            )
            config = scan_config_from_flags(
                target=str(body["target"]),
                max_pages=int(body.get("max_pages", 50)),
                browser=bool(body.get("browser", False)),
                active=bool(body.get("active", False)),
                auth_contexts=auth,
            )
            crawl, findings = await ScannerEngine(
                max_pages=int(body.get("max_pages", 50))
            ).scan(config=config)
            report = build_report(
                crawl,
                findings,
                modes={
                    "browser": bool(body.get("browser", False)),
                    "active": bool(body.get("active", False)),
                    "auth_contexts": len(auth or []),
                },
            )
            snapshot = build_scan_snapshot(
                crawl,
                findings,
                modes=report["modes"],
            )
            persistence.complete_scan(
                scan_id,
                report=report,
                snapshot=snapshot,
                status="completed",
            )
        except Exception as exc:  # noqa: BLE001
            persistence.update_scan_status(
                scan_id,
                "failed",
                error=str(exc),
            )

    @api.post("/targets")
    def post_target(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        item = registry.register(
            str(body["base_url"]),
            environment=str(body.get("environment", "local")),
            trusted_local=bool(body.get("trusted_local", True)),
        )
        persistence.upsert_target(
            item.target_id,
            item.base_url,
            environment=item.environment,
            metadata=item.to_dict(),
        )
        return item.to_dict()

    @api.get("/targets")
    def get_targets() -> list[dict[str, Any]]:
        return persistence.list_targets()

    @api.get("/scans")
    def list_scans(
        target_id: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> list[dict[str, Any]]:
        return persistence.list_scans(target_id=target_id, limit=limit)

    @api.post("/scans")
    async def post_scan(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
        target = str(payload.get("target") or "").strip()
        if not target:
            raise HTTPException(status_code=422, detail="target is required")
        if len(target) > 2048:
            raise HTTPException(status_code=413, detail="target too long")
        max_pages = int(payload.get("max_pages", 50))
        if max_pages < 1 or max_pages > 500:
            raise HTTPException(status_code=422, detail="max_pages out of range")
        auth_path = payload.get("auth_contexts_path")
        if auth_path is not None:
            auth_path_s = str(auth_path)
            if ".." in auth_path_s.replace("\\", "/") or auth_path_s.startswith(
                ("/", "\\")
            ):
                raise HTTPException(
                    status_code=400,
                    detail="auth_contexts_path must be a relative local path",
                )
        tid = target_id_for(target)
        persistence.upsert_target(tid, target)
        scan_id = persistence.create_scan(target_id=tid, status="queued")
        asyncio.create_task(_run_scan_job(scan_id, payload))
        return {
            "id": scan_id,
            "target_id": tid,
            "status": "queued",
        }

    @api.get("/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return row

    @api.get("/scans/{scan_id}/findings")
    def get_findings(scan_id: str) -> list[dict[str, Any]]:
        if persistence.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return persistence.get_findings(scan_id)

    @api.get("/scans/{scan_id}/coverage")
    def get_coverage(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return (row.get("report") or {}).get("coverage") or {}

    @api.get("/scans/{scan_id}/diff")
    def get_diff(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        baseline = persistence.get_baseline(row["target_id"])
        if baseline is None:
            raise HTTPException(status_code=404, detail="baseline missing")
        return diff_snapshots(baseline, row.get("snapshot") or {})

    @api.post("/scans/{scan_id}/baseline")
    def post_baseline(scan_id: str) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        if row.get("status") != "completed":
            raise HTTPException(
                status_code=400,
                detail="baseline requires a completed scan",
            )
        snapshot = row.get("snapshot") or {}
        if not snapshot:
            raise HTTPException(status_code=400, detail="scan has no snapshot")
        persistence.set_baseline(row["target_id"], snapshot)
        return {"ok": True, "target_id": row["target_id"], "scan_id": scan_id}

    @api.get("/scans/{scan_id}/report.html")
    def get_report_html(scan_id: str) -> HTMLResponse:
        row = persistence.get_scan(scan_id)
        if row is None:
            raise HTTPException(status_code=404, detail="scan not found")
        report = row.get("report") or {}
        if not report:
            raise HTTPException(status_code=404, detail="report not ready")
        return HTMLResponse(render_html_report(report))

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(api)

    if WEB_DIST.is_dir():
        assets = WEB_DIST / "assets"
        if assets.is_dir():
            app.mount(
                "/assets",
                StaticFiles(directory=assets),
                name="assets",
            )

        @app.get("/")
        def spa_index() -> FileResponse:
            return FileResponse(WEB_DIST / "index.html")

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str) -> FileResponse:
            candidate = (WEB_DIST / full_path).resolve()
            try:
                candidate.relative_to(WEB_DIST.resolve())
            except ValueError:
                return FileResponse(WEB_DIST / "index.html")
            if full_path and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(WEB_DIST / "index.html")
    else:

        @app.get("/")
        def spa_missing() -> HTMLResponse:
            return HTMLResponse(
                "<!doctype html><html><body style='font-family:system-ui;"
                "background:#121417;color:#e8eaed;padding:2rem'>"
                "<h1>Magic Security</h1>"
                "<p>API is running. Build the dashboard:</p>"
                "<pre style='background:#1c1f24;padding:1rem'>"
                "cd web && npm install && npm run build</pre>"
                "<p>Then restart <code>magic-security serve</code>.</p>"
                "<p>API health: <a href='/api/health' style='color:#e8a838'>"
                "/api/health</a></p>"
                "</body></html>"
            )

    return app
