"""Repository security pack (STEP 47) — source findings only."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from magic_security.framework_analysis import (
    analyze_repository_tree,
    compare_runtime_to_source,
)
from magic_security.models import CrawlResult, NormalizedEndpoint
from magic_security.repo_adapter import RepoRoute, RepoSnapshot, RepositoryAdapter


_SECRET_ASSIGN = re.compile(
    r"""(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"""
)
_DEBUG_PATTERNS = (
    (re.compile(r"(?i)APP_DEBUG\s*=\s*true"), "laravel_debug"),
    (re.compile(r"(?i)DEBUG\s*=\s*True"), "django_debug"),
    (re.compile(r"(?i)NODE_ENV\s*=\s*development"), "node_development"),
)


@dataclass
class RepoSecurityPackResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    snapshot: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def analyze_repo_security(
    root: Path,
    *,
    crawl: CrawlResult | None = None,
    adapter: RepositoryAdapter | None = None,
) -> RepoSecurityPackResult:
    root = Path(root)
    result = RepoSecurityPackResult()
    if adapter is not None:
        snapshot = adapter.load()
    else:
        analysis = analyze_repository_tree(root)
        snapshot = RepoSnapshot(
            repository_id=root.name,
            framework=analysis.get("framework"),
            routes=[
                RepoRoute(
                    path=item["path"],
                    methods=tuple(item.get("methods") or ("GET",)),
                    auth_required=item.get("auth_required"),
                    middleware=tuple(item.get("middleware") or ()),
                    source_file=item.get("source_file"),
                )
                for item in analysis.get("routes") or []
            ],
            auth_controls=list(analysis.get("auth_controls") or []),
            dependency_manifests=list(
                analysis.get("dependency_manifests") or []
            ),
            source_locations=list(analysis.get("source_locations") or []),
        )
    result.snapshot = snapshot.to_dict()

    # Secret-like values — fingerprint/location only.
    for path in list(root.rglob("*"))[:200]:
        if not path.is_file():
            continue
        if path.suffix.lower() not in {
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".php",
            ".env",
            ".yml",
            ".yaml",
            ".json",
            ".toml",
        }:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _SECRET_ASSIGN.finditer(text):
            result.findings.append(
                {
                    "title": "Secret-like assignment in source",
                    "severity": "medium",
                    "kind": "source",
                    "location": str(path.relative_to(root)).replace("\\", "/"),
                    "evidence": (
                        f"name={match.group(1)}; value_fingerprint="
                        f"{_fingerprint(match.group(2))}"
                    ),
                    "evidence_source": "source",
                    "verified_runtime": False,
                }
            )
        for pattern, label in _DEBUG_PATTERNS:
            if pattern.search(text):
                result.findings.append(
                    {
                        "title": f"Debug/development setting ({label})",
                        "severity": "low",
                        "kind": "source",
                        "location": str(path.relative_to(root)).replace("\\", "/"),
                        "evidence": "debug-like configuration observed",
                        "evidence_source": "source",
                        "verified_runtime": False,
                    }
                )

    dockerfile = root / "Dockerfile"
    if dockerfile.exists():
        text = dockerfile.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"(?i)^\s*USER\s+root\s*$", text, re.M):
            result.findings.append(
                {
                    "title": "Dockerfile runs as root",
                    "severity": "low",
                    "kind": "source",
                    "location": "Dockerfile",
                    "evidence": "USER root observed",
                    "evidence_source": "source",
                    "verified_runtime": False,
                }
            )

    for workflow in (root / ".github" / "workflows").glob("*.yml") if (root / ".github" / "workflows").exists() else []:
        text = workflow.read_text(encoding="utf-8", errors="ignore")
        if "pull_request_target" in text and "checkout" in text:
            result.findings.append(
                {
                    "title": "CI workflow uses pull_request_target",
                    "severity": "medium",
                    "kind": "source",
                    "location": str(workflow.relative_to(root)).replace("\\", "/"),
                    "evidence": "pull_request_target with checkout — review carefully",
                    "evidence_source": "source",
                    "verified_runtime": False,
                }
            )

    if crawl is not None:
        runtime_paths = [
            endpoint.url.split("://", 1)[-1].split("/", 1)[-1]
            if "://" in endpoint.url
            else endpoint.url
            for endpoint in crawl.normalized_endpoints
        ]
        # Prefer path-only.
        runtime_paths = []
        for endpoint in crawl.normalized_endpoints:
            from urllib.parse import urlsplit

            runtime_paths.append(urlsplit(endpoint.url).path or "/")
        result.correlations = compare_runtime_to_source(
            runtime_paths,
            snapshot.routes,
        )
        for row in result.correlations:
            if row.get("correlated") and row.get("auth_middleware"):
                result.findings.append(
                    {
                        "title": "Runtime endpoint correlated with source auth middleware",
                        "severity": "info",
                        "kind": "correlated",
                        "location": row.get("source_route"),
                        "evidence": (
                            f"runtime={row.get('runtime_path')}; "
                            f"middleware={row.get('auth_middleware')}"
                        ),
                        "evidence_source": "correlated",
                        "verified_runtime": False,
                    }
                )

    result.coverage = {
        "pack": "repository_security",
        "framework": snapshot.framework,
        "routes": len(snapshot.routes),
        "source_findings": sum(
            1 for item in result.findings if item.get("evidence_source") == "source"
        ),
        "correlated": sum(
            1
            for item in result.findings
            if item.get("evidence_source") == "correlated"
        ),
    }
    return result
