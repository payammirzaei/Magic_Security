"""Persistence abstraction (STEP 48) — SQLite by default."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class Persistence:
    path: Path

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workspaces (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS targets (
                  id TEXT PRIMARY KEY,
                  base_url TEXT NOT NULL,
                  environment TEXT,
                  metadata_json TEXT,
                  workspace_id TEXT NOT NULL DEFAULT 'default'
                );
                CREATE TABLE IF NOT EXISTS scans (
                  id TEXT PRIMARY KEY,
                  target_id TEXT,
                  created_at TEXT,
                  status TEXT,
                  report_json TEXT,
                  snapshot_json TEXT,
                  error_text TEXT
                  ,stage_json TEXT,
                  workspace_id TEXT NOT NULL DEFAULT 'default'
                  ,config_json TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                  id TEXT PRIMARY KEY,
                  scan_id TEXT,
                  fingerprint TEXT,
                  payload_json TEXT
                );
                CREATE TABLE IF NOT EXISTS baselines (
                  target_id TEXT PRIMARY KEY,
                  snapshot_json TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                  token TEXT PRIMARY KEY,
                  expires_at REAL NOT NULL
                );
                """
            )
            conn.execute("INSERT OR IGNORE INTO workspaces(id, name, created_at) VALUES('default', 'Acme Labs', ?)", (datetime.now(timezone.utc).isoformat(),))
            cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(scans)").fetchall()
            }
            if "error_text" not in cols:
                conn.execute("ALTER TABLE scans ADD COLUMN error_text TEXT")
            if "stage_json" not in cols:
                conn.execute("ALTER TABLE scans ADD COLUMN stage_json TEXT")
            if "config_json" not in cols:
                conn.execute("ALTER TABLE scans ADD COLUMN config_json TEXT")
            target_cols = {row[1] for row in conn.execute("PRAGMA table_info(targets)").fetchall()}
            if "workspace_id" not in target_cols:
                conn.execute("ALTER TABLE targets ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'")
            if "workspace_id" not in cols:
                conn.execute("ALTER TABLE scans ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'default'")

    def create_session(self, token: str, expires_at: float) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO sessions(token, expires_at) VALUES(?, ?)", (token, expires_at))

    def get_session_expiry(self, token: str) -> float | None:
        with self.connect() as conn:
            row = conn.execute("SELECT expires_at FROM sessions WHERE token=?", (token,)).fetchone()
        return float(row[0]) if row else None

    def refresh_session(self, token: str, expires_at: float) -> bool:
        with self.connect() as conn:
            result = conn.execute("UPDATE sessions SET expires_at=? WHERE token=?", (expires_at, token))
        return result.rowcount > 0

    def revoke_session(self, token: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))

    def purge_expired_sessions(self, now: float) -> int:
        with self.connect() as conn:
            result = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        return result.rowcount

    def upsert_target(
        self,
        target_id: str,
        base_url: str,
        *,
        environment: str = "local",
        metadata: dict[str, Any] | None = None,
        workspace_id: str = "default",
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO targets(id, base_url, environment, metadata_json, workspace_id)
                VALUES(?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  base_url=excluded.base_url,
                  environment=excluded.environment,
                  metadata_json=excluded.metadata_json
                """,
                (
                    target_id,
                    base_url,
                    environment,
                    json.dumps(metadata or {}),
                    workspace_id,
                ),
            )

    def list_targets(self, *, limit: int = 200, offset: int = 0, workspace_id: str = "default") -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM targets WHERE workspace_id=? ORDER BY base_url LIMIT ? OFFSET ?", (workspace_id, limit, offset)).fetchall()
            scans = conn.execute("SELECT id, target_id, created_at, status, report_json FROM scans WHERE workspace_id=? ORDER BY created_at DESC", (workspace_id,)).fetchall()
            finding_rows = conn.execute("SELECT scan_id, payload_json FROM findings JOIN scans ON scans.id=findings.scan_id WHERE scans.workspace_id=?", (workspace_id,)).fetchall()
        latest: dict[str, dict[str, Any]] = {}
        open_counts: dict[str, int] = {}
        for finding in finding_rows:
            payload = json.loads(finding["payload_json"] or "{}")
            if payload.get("status", "open") == "open":
                open_counts[str(finding["scan_id"])] = open_counts.get(str(finding["scan_id"]), 0) + 1
        for scan in scans:
            target_id = str(scan["target_id"])
            if target_id in latest:
                continue
            report = json.loads(scan["report_json"] or "{}")
            summary = dict(report.get("summary") or {})
            if scan["status"] == "completed":
                summary["findings"] = open_counts.get(str(scan["id"]), 0)
            latest[target_id] = {"last_scan_at": scan["created_at"], "last_scan_status": scan["status"], "last_scan_summary": summary}
        result = []
        for row in rows:
            item = dict(row)
            item.update(latest.get(item["id"], {"last_scan_at": None, "last_scan_status": None, "last_scan_summary": {}}))
            result.append(item)
        return result

    def create_scan(
        self,
        *,
        target_id: str,
        status: str = "queued",
        scan_id: str | None = None,
        config: dict[str, Any] | None = None,
        workspace_id: str = "default",
    ) -> str:
        sid = scan_id or uuid.uuid4().hex
        created = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scans(
                  id, target_id, created_at, status, report_json, snapshot_json, error_text, stage_json, config_json, workspace_id
                )
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (sid, target_id, created, status, "{}", "{}", None, json.dumps({"current": "queued", "completed": [], "progress": 0}), json.dumps(config or {}), workspace_id),
            )
        return sid

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        *,
        error: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status=?, error_text=COALESCE(?, error_text)
                WHERE id=?
                """,
                (status, error, scan_id),
            )

    def delete_target(self, target_id: str, *, workspace_id: str = "default") -> bool:
        with self.connect() as conn:
            active = conn.execute("SELECT 1 FROM scans WHERE target_id=? AND workspace_id=? AND status IN ('queued','running') LIMIT 1", (target_id, workspace_id)).fetchone()
            if active:
                return False
            result = conn.execute("DELETE FROM targets WHERE id=? AND workspace_id=?", (target_id, workspace_id))
            return result.rowcount > 0

    def list_workspaces(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT id, name, created_at FROM workspaces ORDER BY name").fetchall()
        return [dict(row) for row in rows]

    def create_workspace(self, workspace_id: str, name: str) -> dict[str, Any]:
        created = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute("INSERT INTO workspaces(id, name, created_at) VALUES(?,?,?)", (workspace_id, name, created))
        return {"id": workspace_id, "name": name, "created_at": created}

    def rename_workspace(self, workspace_id: str, name: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            result = conn.execute("UPDATE workspaces SET name=? WHERE id=?", (name, workspace_id))
            if result.rowcount == 0:
                return None
            row = conn.execute("SELECT id, name, created_at FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
        return dict(row) if row else None

    def update_scan_stage(self, scan_id: str, stage: str, *, progress: int, completed: list[str] | None = None) -> None:
        payload = {"current": stage, "completed": completed or [], "progress": max(0, min(100, progress))}
        with self.connect() as conn:
            conn.execute("UPDATE scans SET stage_json=? WHERE id=?", (json.dumps(payload), scan_id))

    def list_pending_scans(self, *, workspace_id: str = "default") -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, target_id, status, config_json FROM scans WHERE workspace_id=? AND status IN ('queued','running') ORDER BY created_at",
                (workspace_id,),
            ).fetchall()
        pending: list[dict[str, Any]] = []
        for row in rows:
            pending.append({"id": row["id"], "target_id": row["target_id"], "status": row["status"], "config": json.loads(row["config_json"] or "{}")})
        return pending

    def complete_scan(
        self,
        scan_id: str,
        *,
        report: dict[str, Any],
        snapshot: dict[str, Any] | None = None,
        status: str = "completed",
        error: str | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status=?, report_json=?, snapshot_json=?, error_text=?
                WHERE id=?
                """,
                (
                    status,
                    json.dumps(report),
                    json.dumps(snapshot or {}),
                    error,
                    scan_id,
                ),
            )
            conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            for finding in report.get("findings") or []:
                conn.execute(
                    """
                    INSERT INTO findings(id, scan_id, fingerprint, payload_json)
                    VALUES(?,?,?,?)
                    """,
                    (
                        uuid.uuid4().hex,
                        scan_id,
                        finding.get("fingerprint"),
                        json.dumps(finding),
                    ),
                )

    def save_scan(
        self,
        *,
        target_id: str,
        report: dict[str, Any],
        snapshot: dict[str, Any] | None = None,
        status: str = "completed",
    ) -> str:
        scan_id = self.create_scan(target_id=target_id, status=status)
        self.complete_scan(
            scan_id,
            report=report,
            snapshot=snapshot,
            status=status,
        )
        return scan_id

    def list_scans(
        self,
        *,
        target_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
        workspace_id: str = "default",
    ) -> list[dict[str, Any]]:
        query = """
            SELECT id, target_id, created_at, status, error_text, report_json, stage_json
            FROM scans WHERE workspace_id=?
        """
        params: list[Any] = [workspace_id]
        if target_id:
            query += " AND target_id=?"
            params.append(target_id)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            report = json.loads(data.pop("report_json") or "{}")
            data["stage"] = json.loads(data.pop("stage_json") or "{}")
            data["summary"] = report.get("summary")
            data["scan_validity"] = report.get("scan_validity")
            data["error"] = data.pop("error_text", None)
            results.append(data)
        return results

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["report"] = json.loads(data.pop("report_json") or "{}")
        data["snapshot"] = json.loads(data.pop("snapshot_json") or "{}")
        data["stage"] = json.loads(data.pop("stage_json") or "{}")
        data["config"] = json.loads(data.pop("config_json") or "{}")
        data["error"] = data.pop("error_text", None)
        data["summary"] = (data["report"] or {}).get("summary")
        return data

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def list_findings(self, *, limit: int = 200, offset: int = 0, workspace_id: str = "default") -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT f.payload_json, s.target_id, s.created_at
                FROM findings f JOIN scans s ON s.id = f.scan_id
                WHERE s.workspace_id=? ORDER BY s.created_at DESC LIMIT ? OFFSET ?
                """,
                (workspace_id, limit, offset),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = json.loads(row["payload_json"] or "{}")
            item["target_id"] = row["target_id"]
            item["detected_at"] = row["created_at"]
            result.append(item)
        return result

    def update_finding_status(self, identifier: str, status: str, *, workspace_id: str = "default") -> dict[str, Any] | None:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT f.id, f.payload_json FROM findings f JOIN scans s ON s.id=f.scan_id WHERE s.workspace_id=?",
                (workspace_id,),
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"] or "{}")
                if payload.get("fingerprint") != identifier and payload.get("check_id") != identifier:
                    continue
                payload["status"] = status
                conn.execute("UPDATE findings SET payload_json=? WHERE id=?", (json.dumps(payload), row["id"]))
                return payload
        return None

    def get_finding(self, identifier: str, *, workspace_id: str = "default") -> dict[str, Any] | None:
        items = self.list_findings(limit=1000, workspace_id=workspace_id)
        return next((item for item in items if item.get("fingerprint") == identifier or item.get("check_id") == identifier), None)

    def set_baseline(self, target_id: str, snapshot: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO baselines(target_id, snapshot_json)
                VALUES(?,?)
                ON CONFLICT(target_id) DO UPDATE SET snapshot_json=excluded.snapshot_json
                """,
                (target_id, json.dumps(snapshot)),
            )

    def get_baseline(self, target_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT snapshot_json FROM baselines WHERE target_id=?",
                (target_id,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["snapshot_json"])
