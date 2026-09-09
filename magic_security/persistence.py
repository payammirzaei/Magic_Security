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
                CREATE TABLE IF NOT EXISTS targets (
                  id TEXT PRIMARY KEY,
                  base_url TEXT NOT NULL,
                  environment TEXT,
                  metadata_json TEXT
                );
                CREATE TABLE IF NOT EXISTS scans (
                  id TEXT PRIMARY KEY,
                  target_id TEXT,
                  created_at TEXT,
                  status TEXT,
                  report_json TEXT,
                  snapshot_json TEXT
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

    def upsert_target(
        self,
        target_id: str,
        base_url: str,
        *,
        environment: str = "local",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO targets(id, base_url, environment, metadata_json)
                VALUES(?,?,?,?)
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
                ),
            )

    def list_targets(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM targets ORDER BY base_url").fetchall()
        return [dict(row) for row in rows]

    def save_scan(
        self,
        *,
        target_id: str,
        report: dict[str, Any],
        snapshot: dict[str, Any] | None = None,
        status: str = "completed",
    ) -> str:
        scan_id = uuid.uuid4().hex
        created = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO scans(id, target_id, created_at, status, report_json, snapshot_json)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    scan_id,
                    target_id,
                    created,
                    status,
                    json.dumps(report),
                    json.dumps(snapshot or {}),
                ),
            )
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
        return scan_id

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
        return data

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM findings WHERE scan_id=?",
                (scan_id,),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

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
