"""Local FastAPI control plane — API under /api, SPA from web/dist."""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
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
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
        from fastapi.staticfiles import StaticFiles
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "Install magic-security[api] (fastapi/uvicorn) to use the local API"
        ) from exc

    app = FastAPI(title="Magic Security Local API", version="1.0")
    api_key = os.environ.get("MAGIC_SECURITY_API_KEY")

    @app.middleware("http")
    async def api_auth_guard(request, call_next):
        if api_key and request.url.path.startswith("/api/") and request.url.path != "/api/health":
            supplied = request.headers.get("authorization", "")
            expected = f"Bearer {api_key}"
            if not hmac.compare_digest(supplied, expected):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
        return await call_next(request)
    api = APIRouter(prefix="/api")
    persistence = Persistence(Path(db_path))
    persistence.init_schema()
    registry = TargetRegistry()
    scan_queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
    cancelled_scans: set[str] = set()

    async def _run_scan_job(scan_id: str, body: dict[str, Any]) -> None:
        from magic_security.auth import load_auth_contexts
        from magic_security.config import scan_config_from_flags

        persistence.update_scan_status(scan_id, "running")
        completed_stages: list[str] = []
        try:
            persistence.update_scan_stage(scan_id, "preflight", progress=8)
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
            persistence.update_scan_stage(scan_id, "discovery", progress=20, completed=["preflight"])
            crawl, findings = await ScannerEngine(
                max_pages=int(body.get("max_pages", 50))
            ).scan(config=config)
            if scan_id in cancelled_scans:
                persistence.update_scan_status(scan_id, "cancelled")
                return
            completed_stages = ["preflight", "discovery"]
            persistence.update_scan_stage(scan_id, "security_checks", progress=62, completed=completed_stages)
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
            persistence.update_scan_stage(scan_id, "report", progress=88, completed=["preflight", "discovery", "security_checks"])
            persistence.complete_scan(
                scan_id,
                report=report,
                snapshot=snapshot,
                status="completed",
            )
            persistence.update_scan_stage(scan_id, "complete", progress=100, completed=["preflight", "discovery", "security_checks", "report"])
        except Exception as exc:  # noqa: BLE001
            persistence.update_scan_status(
                scan_id,
                "failed",
                error=str(exc),
            )

    async def _scan_worker() -> None:
        while True:
            scan_id, body = await scan_queue.get()
            try:
                await _run_scan_job(scan_id, body)
            finally:
                scan_queue.task_done()

    @app.on_event("startup")
    async def start_scan_worker() -> None:
        app.state.scan_workers = [asyncio.create_task(_scan_worker()) for _ in range(2)]
        for pending in persistence.list_pending_scans():
            persistence.update_scan_status(pending["id"], "queued")
            await scan_queue.put((pending["id"], pending["config"]))

    @app.on_event("shutdown")
    async def stop_scan_worker() -> None:
        workers = getattr(app.state, "scan_workers", [])
        for worker in workers:
            worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

    @api.post("/targets")
    def post_target(body: dict[str, Any] = Body(...), workspace_id: str = Query(default="default")) -> dict[str, Any]:
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
            workspace_id=workspace_id,
        )
        return item.to_dict()

    @api.get("/targets")
    def get_targets(workspace_id: str = Query(default="default")) -> list[dict[str, Any]]:
        return persistence.list_targets(workspace_id=workspace_id)

    @api.delete("/targets/{target_id}")
    def delete_target(target_id: str, workspace_id: str = Query(default="default")) -> dict[str, Any]:
        if not any(item.get("id") == target_id for item in persistence.list_targets(workspace_id=workspace_id)):
            raise HTTPException(status_code=404, detail="target not found")
        if not persistence.delete_target(target_id, workspace_id=workspace_id):
            raise HTTPException(status_code=409, detail="target has an active scan")
        return {"ok": True, "id": target_id}

    @api.get("/scans")
    def list_scans(
        target_id: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        workspace_id: str = Query(default="default"),
    ) -> list[dict[str, Any]]:
        return persistence.list_scans(target_id=target_id, limit=limit, workspace_id=workspace_id)

    @api.get("/findings")
    def get_all_findings(
        limit: int = Query(default=200, ge=1, le=1000),
        workspace_id: str = Query(default="default"),
    ) -> list[dict[str, Any]]:
        return persistence.list_findings(limit=limit, workspace_id=workspace_id)

    @api.get("/findings/{finding_id}")
    def get_finding(finding_id: str, workspace_id: str = Query(default="default")) -> dict[str, Any]:
        finding = persistence.get_finding(finding_id, workspace_id=workspace_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding

    @api.patch("/findings/{finding_id}/status")
    def update_finding_status(finding_id: str, body: dict[str, Any] = Body(...), workspace_id: str = Query(default="default")) -> dict[str, Any]:
        status = str(body.get("status", "")).lower()
        if status not in {"open", "triaged", "ignored"}:
            raise HTTPException(status_code=422, detail="status must be open, triaged or ignored")
        finding = persistence.update_finding_status(finding_id, status, workspace_id=workspace_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding

    @api.post("/scans")
    async def post_scan(payload: dict[str, Any] = Body(...), workspace_id: str = Query(default="default")) -> dict[str, Any]:
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
        persistence.upsert_target(tid, target, workspace_id=workspace_id)
        scan_id = persistence.create_scan(target_id=tid, status="queued", config=payload, workspace_id=workspace_id)
        await scan_queue.put((scan_id, payload))
        return {
            "id": scan_id,
            "target_id": tid,
            "status": "queued",
        }

    @api.get("/scans/{scan_id}")
    def get_scan(scan_id: str, workspace_id: str = Query(default="default")) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        return row

    @api.get("/scans/{scan_id}/findings")
    def get_findings(scan_id: str, workspace_id: str = Query(default="default")) -> list[dict[str, Any]]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        return persistence.get_findings(scan_id)

    @api.get("/scans/{scan_id}/events")
    async def scan_events(scan_id: str, workspace_id: str = Query(default="default")) -> StreamingResponse:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")

        async def stream():
            last = None
            for _ in range(240):
                current = persistence.get_scan(scan_id)
                if current is None:
                    break
                payload = {"id": scan_id, "status": current["status"], "stage": current.get("stage") or {}}
                marker = repr(payload)
                if marker != last:
                    last = marker
                    yield f"event: scan\ndata: {json.dumps(payload)}\n\n"
                if current["status"] in {"completed", "failed", "cancelled"}:
                    break
                await asyncio.sleep(1)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @api.get("/scans/{scan_id}/coverage")
    def get_coverage(scan_id: str, workspace_id: str = Query(default="default")) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        return (row.get("report") or {}).get("coverage") or {}

    @api.get("/scans/{scan_id}/diff")
    def get_diff(scan_id: str, workspace_id: str = Query(default="default")) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        baseline = persistence.get_baseline(row["target_id"])
        if baseline is None:
            raise HTTPException(status_code=404, detail="baseline missing")
        return diff_snapshots(baseline, row.get("snapshot") or {})

    @api.post("/scans/{scan_id}/baseline")
    def post_baseline(scan_id: str, workspace_id: str = Query(default="default")) -> dict[str, Any]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
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
    def get_report_html(scan_id: str, workspace_id: str = Query(default="default")) -> HTMLResponse:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        report = row.get("report") or {}
        if not report:
            raise HTTPException(status_code=404, detail="report not ready")
        return HTMLResponse(render_html_report(report))

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/workspace")
    def workspace(workspace_id: str = Query(default="default")) -> dict[str, str]:
        item = next((entry for entry in persistence.list_workspaces() if entry["id"] == workspace_id), None)
        if item is None:
            raise HTTPException(status_code=404, detail="workspace not found")
        return {"id": item["id"], "name": item["name"]}

    @api.get("/workspaces")
    def workspaces() -> list[dict[str, Any]]:
        return persistence.list_workspaces()

    @api.post("/workspaces")
    def create_workspace(body: dict[str, Any] = Body(...)) -> dict[str, Any]:
        name = str(body.get("name", "")).strip()
        if not name or len(name) > 80:
            raise HTTPException(status_code=422, detail="workspace name must be 1-80 characters")
        workspace_id = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40]
        if not workspace_id:
            raise HTTPException(status_code=422, detail="workspace name must contain letters or numbers")
        if any(item["id"] == workspace_id for item in persistence.list_workspaces()):
            raise HTTPException(status_code=409, detail="workspace already exists")
        return persistence.create_workspace(workspace_id, name)

    @api.get("/me")
    def current_user() -> dict[str, Any]:
        return {
            "id": "local-owner",
            "name": "Payam",
            "email": None,
            "role": "owner",
            "workspace": {"id": "default", "name": "Acme Labs"},
            "authenticated": False,
        }

    @api.get("/queue")
    def queue_status() -> dict[str, int]:
        return {"queued": scan_queue.qsize(), "workers": 2}

    @api.post("/scans/{scan_id}/cancel")
    async def cancel_scan(scan_id: str, workspace_id: str = Query(default="default")) -> dict[str, str]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        if row["status"] not in {"queued", "running"}:
            raise HTTPException(status_code=409, detail="scan is not active")
        cancelled_scans.add(scan_id)
        persistence.update_scan_status(scan_id, "cancelled")
        return {"id": scan_id, "status": "cancelled"}

    @api.post("/scans/{scan_id}/retry")
    async def retry_scan(scan_id: str, workspace_id: str = Query(default="default")) -> dict[str, str]:
        row = persistence.get_scan(scan_id)
        if row is None or row.get("workspace_id", "default") != workspace_id:
            raise HTTPException(status_code=404, detail="scan not found")
        if row["status"] not in {"failed", "cancelled"}:
            raise HTTPException(status_code=409, detail="only failed or cancelled scans can be retried")
        config = row.get("config") or {"target": row["target_id"]}
        new_id = persistence.create_scan(target_id=row["target_id"], status="queued", config=config, workspace_id=workspace_id)
        await scan_queue.put((new_id, config))
        return {"id": new_id, "status": "queued"}

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
