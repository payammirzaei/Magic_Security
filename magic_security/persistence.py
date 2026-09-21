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

    def list_targets(self, *, workspace_id: str = "default") -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM targets WHERE workspace_id=? ORDER BY base_url", (workspace_id,)).fetchall()
        return [dict(row) for row in rows]

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

    def list_workspaces(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT id, name, created_at FROM workspaces ORDER BY name").fetchall()
        return [dict(row) for row in rows]

    def update_scan_stage(self, scan_id: str, stage: str, *, progress: int, completed: list[str] | None = None) -> None:
        payload = {"current": stage, "completed": completed or [], "progress": max(0, min(100, progress))}
        with self.connect() as conn:
            conn.execute("UPDATE scans SET stage_json=? WHERE id=?", (json.dumps(payload), scan_id))

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
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
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

    def list_findings(self, *, limit: int = 200, workspace_id: str = "default") -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT f.payload_json, s.target_id, s.created_at
                FROM findings f JOIN scans s ON s.id = f.scan_id
                WHERE s.workspace_id=? ORDER BY s.created_at DESC LIMIT ?
                """,
                (workspace_id, limit),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = json.loads(row["payload_json"] or "{}")
            item["target_id"] = row["target_id"]
            item["detected_at"] = row["created_at"]
            result.append(item)
        return result

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
