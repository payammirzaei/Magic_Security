"""Dependency / supply-chain inventory (STEP 69)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DependencyRecord:
    name: str
    version: str | None
    ecosystem: str
    source_file: str
    confidence: str = "inventory"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "source_file": self.source_file,
            "confidence": self.confidence,
            "vulnerability_status": "not_assessed",
        }


@dataclass
class DependencyInventory:
    dependencies: list[DependencyRecord] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifests": list(self.manifests),
            "dependencies": [item.to_dict() for item in self.dependencies],
            "note": "Inventory only — no advisory CVE status claimed",
        }


_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=)?\s*([^\s;#]*)?"
)


def inventory_dependencies(root: Path) -> DependencyInventory:
    root = Path(root)
    result = DependencyInventory()

    lock_handlers = {
        "package-lock.json": _from_package_lock,
        "pnpm-lock.yaml": _from_pnpm_lock_stub,
        "yarn.lock": _from_yarn_lock_stub,
        "composer.lock": _from_composer_lock,
        "requirements.txt": _from_requirements,
        "poetry.lock": _from_poetry_lock_stub,
        "uv.lock": _from_uv_lock_stub,
    }
    for name, handler in lock_handlers.items():
        path = root / name
        if path.exists():
            result.manifests.append(name)
            result.dependencies.extend(handler(path))

    dockerfile = root / "Dockerfile"
    if dockerfile.exists():
        result.manifests.append("Dockerfile")
        result.dependencies.extend(_from_dockerfile(dockerfile))

    gh = root / ".github" / "workflows"
    if gh.is_dir():
        for wf in gh.glob("*.yml"):
            result.manifests.append(str(wf.relative_to(root)))
            result.dependencies.extend(_from_gha(wf))

    return result


def _from_package_lock(path: Path) -> list[DependencyRecord]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[DependencyRecord] = []
    packages = data.get("packages") or {}
    for key, meta in packages.items():
        if not key or key == "":
            continue
        name = key.split("node_modules/")[-1]
        out.append(
            DependencyRecord(
                name=name,
                version=(meta or {}).get("version"),
                ecosystem="npm",
                source_file=path.name,
            )
        )
    return out[:500]


def _from_composer_lock(path: Path) -> list[DependencyRecord]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for pkg in data.get("packages") or []:
        out.append(
            DependencyRecord(
                name=str(pkg.get("name")),
                version=str(pkg.get("version")),
                ecosystem="composer",
                source_file=path.name,
            )
        )
    return out


def _from_requirements(path: Path) -> list[DependencyRecord]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        out.append(
            DependencyRecord(
                name=match.group(1),
                version=match.group(2) or None,
                ecosystem="pip",
                source_file=path.name,
            )
        )
    return out


def _from_pnpm_lock_stub(path: Path) -> list[DependencyRecord]:
    return [
        DependencyRecord(
            name="(pnpm-lock present)",
            version=None,
            ecosystem="pnpm",
            source_file=path.name,
            confidence="manifest_only",
        )
    ]


def _from_yarn_lock_stub(path: Path) -> list[DependencyRecord]:
    return [
        DependencyRecord(
            name="(yarn.lock present)",
            version=None,
            ecosystem="yarn",
            source_file=path.name,
            confidence="manifest_only",
        )
    ]


def _from_poetry_lock_stub(path: Path) -> list[DependencyRecord]:
    return [
        DependencyRecord(
            name="(poetry.lock present)",
            version=None,
            ecosystem="poetry",
            source_file=path.name,
            confidence="manifest_only",
        )
    ]


def _from_uv_lock_stub(path: Path) -> list[DependencyRecord]:
    return [
        DependencyRecord(
            name="(uv.lock present)",
            version=None,
            ecosystem="uv",
            source_file=path.name,
            confidence="manifest_only",
        )
    ]


def _from_dockerfile(path: Path) -> list[DependencyRecord]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.upper().startswith("FROM "):
            image = line.split(None, 1)[1].strip()
            out.append(
                DependencyRecord(
                    name=image.split(":")[0],
                    version=image.split(":")[1] if ":" in image else None,
                    ecosystem="docker",
                    source_file=path.name,
                )
            )
    return out


def _from_gha(path: Path) -> list[DependencyRecord]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "uses:" in line:
            action = line.split("uses:", 1)[1].strip().strip("'\"")
            name, _, version = action.partition("@")
            out.append(
                DependencyRecord(
                    name=name,
                    version=version or None,
                    ecosystem="github-actions",
                    source_file=path.name,
                )
            )
    return out
