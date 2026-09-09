"""Persistent local scan history and baselines (STEP 39)."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from magic_security.backtesting import write_snapshot


DEFAULT_ROOT = Path(".magic-security")


def target_id_for(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "unknown").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    raw = f"{parts.scheme}://{host}:{port}{parts.path.rstrip('/') or ''}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    safe_host = re.sub(r"[^a-zA-Z0-9.-]+", "-", host)
    return f"{safe_host}-{port}-{digest}"


class HistoryStore:
    def __init__(self, root: Path | str = DEFAULT_ROOT) -> None:
        self.root = Path(root)

    def target_dir(self, target: str) -> Path:
        return self.root / "targets" / target_id_for(target)

    def scans_dir(self, target: str) -> Path:
        return self.target_dir(target) / "scans"

    def baselines_dir(self, target: str) -> Path:
        return self.target_dir(target) / "baselines"

    def add_target(self, target: str, *, metadata: dict[str, Any] | None = None) -> Path:
        path = self.target_dir(target)
        path.mkdir(parents=True, exist_ok=True)
        self.scans_dir(target).mkdir(parents=True, exist_ok=True)
        self.baselines_dir(target).mkdir(parents=True, exist_ok=True)
        meta_path = path / "target.json"
        payload = {
            "target": target,
            "target_id": target_id_for(target),
            "created_at": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }
        if not meta_path.exists():
            meta_path.write_text(
                json.dumps(payload, indent=2),
                encoding="utf-8",
            )
        return path

    def save_scan(
        self,
        target: str,
        snapshot: dict[str, Any],
        *,
        label: str | None = None,
    ) -> Path:
        self.add_target(target)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = label or f"scan-{stamp}.json"
        path = self.scans_dir(target) / name
        write_snapshot(path, snapshot)
        latest = self.target_dir(target) / "latest.json"
        write_snapshot(latest, snapshot)
        return path

    def set_baseline(
        self,
        target: str,
        snapshot: dict[str, Any] | Path,
        *,
        name: str = "default.json",
    ) -> Path:
        self.add_target(target)
        destination = self.baselines_dir(target) / name
        if isinstance(snapshot, Path):
            data = json.loads(snapshot.read_text(encoding="utf-8"))
        else:
            data = snapshot
        write_snapshot(destination, data)
        return destination

    def get_baseline(
        self,
        target: str,
        *,
        name: str = "default.json",
    ) -> Path | None:
        path = self.baselines_dir(target) / name
        return path if path.exists() else None

    def list_scans(self, target: str) -> list[Path]:
        directory = self.scans_dir(target)
        if not directory.exists():
            return []
        return sorted(directory.glob("*.json"))

    def list_targets(self) -> list[dict[str, Any]]:
        root = self.root / "targets"
        if not root.exists():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(root.iterdir()):
            meta = path / "target.json"
            if meta.exists():
                rows.append(json.loads(meta.read_text(encoding="utf-8")))
            else:
                rows.append({"target_id": path.name})
        return rows
