"""Repository adapter framework (STEP 45)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass
class RepoRoute:
    path: str
    methods: tuple[str, ...] = ("GET",)
    auth_required: bool | None = None
    middleware: tuple[str, ...] = ()
    source_file: str | None = None


@dataclass
class RepoSnapshot:
    repository_id: str
    commit: str | None = None
    framework: str | None = None
    routes: list[RepoRoute] = field(default_factory=list)
    auth_controls: list[str] = field(default_factory=list)
    config_findings: list[dict[str, Any]] = field(default_factory=list)
    dependency_manifests: list[str] = field(default_factory=list)
    source_locations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "commit": self.commit,
            "framework": self.framework,
            "routes": [
                {
                    "path": route.path,
                    "methods": list(route.methods),
                    "auth_required": route.auth_required,
                    "middleware": list(route.middleware),
                    "source_file": route.source_file,
                }
                for route in self.routes
            ],
            "auth_controls": list(self.auth_controls),
            "config_findings": list(self.config_findings),
            "dependency_manifests": list(self.dependency_manifests),
            "source_locations": list(self.source_locations),
            "evidence_source": "repository",
        }


class RepositoryAdapter(Protocol):
    def load(self) -> RepoSnapshot: ...


@dataclass
class MockRepositoryAdapter:
    """Deterministic adapter for tests — never upgrades smells to verified vulns."""

    repository_id: str = "mock-repo"
    commit: str = "deadbeef"
    framework: str = "nextjs"
    routes: list[RepoRoute] = field(
        default_factory=lambda: [
            RepoRoute(
                path="/api/me",
                methods=("GET",),
                auth_required=True,
                middleware=("auth",),
                source_file="app/api/me/route.ts",
            ),
            RepoRoute(
                path="/api/accounts/[id]",
                methods=("GET",),
                auth_required=True,
                middleware=("auth",),
                source_file="app/api/accounts/[id]/route.ts",
            ),
            RepoRoute(
                path="/public",
                methods=("GET",),
                auth_required=False,
                source_file="app/public/page.tsx",
            ),
        ]
    )

    def load(self) -> RepoSnapshot:
        return RepoSnapshot(
            repository_id=self.repository_id,
            commit=self.commit,
            framework=self.framework,
            routes=list(self.routes),
            auth_controls=["middleware:auth"],
            config_findings=[],
            dependency_manifests=["package.json"],
            source_locations=["app/"],
        )


@dataclass
class LocalPathRepositoryAdapter:
    root: Path
    repository_id: str | None = None

    def load(self) -> RepoSnapshot:
        from magic_security.framework_analysis import analyze_repository_tree

        root = Path(self.root)
        analysis = analyze_repository_tree(root)
        return RepoSnapshot(
            repository_id=self.repository_id or root.name,
            commit=None,
            framework=analysis.get("framework"),
            routes=[
                (
                    RepoRoute(
                        path=str(item["path"]),
                        methods=tuple(item.get("methods") or ("GET",)),
                        auth_required=item.get("auth_required"),
                        middleware=tuple(item.get("middleware") or ()),
                        source_file=item.get("source_file"),
                    )
                    if isinstance(item, dict)
                    else item
                )
                for item in analysis.get("routes", [])
            ],
            auth_controls=list(analysis.get("auth_controls") or []),
            config_findings=list(analysis.get("config_findings") or []),
            dependency_manifests=list(analysis.get("dependency_manifests") or []),
            source_locations=list(analysis.get("source_locations") or []),
        )
