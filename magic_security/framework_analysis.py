"""Framework-aware source analysis (STEP 46)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from magic_security.repo_adapter import RepoRoute


_NEXT_APP_ROUTE = re.compile(
    r"(?:^|/)app/(?P<route>.+?)/route\.(?:ts|js|tsx|jsx)$"
)
_NEXT_PAGES_API = re.compile(
    r"(?:^|/)pages/api/(?P<route>.+)\.(?:ts|js)$"
)
_LARAVEL_ROUTE = re.compile(
    r"""Route::(?P<method>get|post|put|patch|delete|options|any)\(\s*['\"](?P<path>[^'\"]+)['\"]""",
    re.I,
)
_LARAVEL_MIDDLEWARE = re.compile(
    r"""->middleware\(\s*\[?(?P<mw>[^\)]+)\]?\)""",
    re.I,
)
_FASTAPI_ROUTE = re.compile(
    r"""@(?:app|router)\.(?P<method>get|post|put|patch|delete)\(\s*['\"](?P<path>[^'\"]+)['\"]""",
    re.I,
)
_EXPRESS_ROUTE = re.compile(
    r"""(?:app|router)\.(?P<method>get|post|put|patch|delete)\(\s*['\"](?P<path>[^'\"]+)['\"]""",
    re.I,
)


def _normalize_next_path(route: str) -> str:
    parts = []
    for segment in route.split("/"):
        if segment.startswith("(") and segment.endswith(")"):
            continue
        if segment.startswith("[") and segment.endswith("]"):
            inner = segment[1:-1]
            if inner.startswith("..."):
                parts.append("{" + inner[3:] + "}")
            else:
                parts.append("{" + inner + "}")
        else:
            parts.append(segment)
    path = "/" + "/".join(parts)
    return path.replace("//", "/")


def detect_framework(root: Path) -> str | None:
    if (root / "next.config.js").exists() or (root / "next.config.mjs").exists():
        return "nextjs"
    if (root / "artisan").exists() or (root / "composer.json").exists():
        text = ""
        composer = root / "composer.json"
        if composer.exists():
            text = composer.read_text(encoding="utf-8", errors="ignore")
        if "laravel" in text.lower() or (root / "artisan").exists():
            return "laravel"
    if (root / "pyproject.toml").exists() or list(root.glob("**/main.py")):
        # Heuristic FastAPI
        for path in list(root.rglob("*.py"))[:40]:
            try:
                body = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "FastAPI(" in body or "from fastapi" in body:
                return "fastapi"
    if (root / "package.json").exists():
        text = (root / "package.json").read_text(encoding="utf-8", errors="ignore")
        if "express" in text.lower():
            return "express"
        if "next" in text.lower():
            return "nextjs"
    return None


def extract_nextjs_routes(root: Path) -> list[RepoRoute]:
    routes: list[RepoRoute] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.as_posix()
        match = _NEXT_APP_ROUTE.search(rel) or _NEXT_PAGES_API.search(rel)
        if not match:
            continue
        route_path = _normalize_next_path(match.group("route"))
        if route_path.endswith("/route"):
            route_path = route_path[: -len("/route")] or "/"
        auth = None
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"getServerSession|auth\(|middleware", text):
                auth = True
        except OSError:
            text = ""
        routes.append(
            RepoRoute(
                path=route_path if route_path.startswith("/") else "/" + route_path,
                methods=("GET", "POST"),
                auth_required=auth,
                middleware=("auth",) if auth else (),
                source_file=str(path.relative_to(root)).replace("\\", "/"),
            )
        )
    return routes


def extract_laravel_routes(root: Path) -> list[RepoRoute]:
    routes: list[RepoRoute] = []
    candidates = [
        root / "routes" / "web.php",
        root / "routes" / "api.php",
    ]
    for file_path in candidates:
        if not file_path.exists():
            continue
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        for match in _LARAVEL_ROUTE.finditer(text):
            method = match.group("method").upper()
            if method == "ANY":
                methods = ("GET", "POST", "PUT", "PATCH", "DELETE")
            else:
                methods = (method,)
            path = match.group("path")
            if not path.startswith("/"):
                path = "/" + path
            snippet = text[match.end() : match.end() + 120]
            mw_match = _LARAVEL_MIDDLEWARE.search(snippet)
            middleware = ()
            auth = None
            if mw_match:
                raw = mw_match.group("mw")
                names = tuple(
                    part.strip().strip("'\"")
                    for part in raw.split(",")
                    if part.strip()
                )
                middleware = names
                auth = any("auth" in name.lower() for name in names)
            routes.append(
                RepoRoute(
                    path=path,
                    methods=methods,
                    auth_required=auth,
                    middleware=middleware,
                    source_file=str(file_path.relative_to(root)).replace("\\", "/"),
                )
            )
    return routes


def extract_fastapi_routes(root: Path) -> list[RepoRoute]:
    routes: list[RepoRoute] = []
    for path in list(root.rglob("*.py"))[:80]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _FASTAPI_ROUTE.finditer(text):
            routes.append(
                RepoRoute(
                    path=match.group("path"),
                    methods=(match.group("method").upper(),),
                    auth_required=None,
                    source_file=str(path.relative_to(root)).replace("\\", "/"),
                )
            )
    return routes


def extract_express_routes(root: Path) -> list[RepoRoute]:
    routes: list[RepoRoute] = []
    for path in list(root.rglob("*.js"))[:80] + list(root.rglob("*.ts"))[:80]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _EXPRESS_ROUTE.finditer(text):
            routes.append(
                RepoRoute(
                    path=match.group("path"),
                    methods=(match.group("method").upper(),),
                    source_file=str(path.relative_to(root)).replace("\\", "/"),
                )
            )
    return routes


def analyze_repository_tree(root: Path) -> dict[str, Any]:
    root = Path(root)
    framework = detect_framework(root)
    routes: list[RepoRoute] = []
    if framework == "nextjs":
        routes = extract_nextjs_routes(root)
    elif framework == "laravel":
        routes = extract_laravel_routes(root)
    elif framework == "fastapi":
        routes = extract_fastapi_routes(root)
    elif framework == "express":
        routes = extract_express_routes(root)
    else:
        # Try common extractors lightly.
        routes = (
            extract_nextjs_routes(root)
            or extract_laravel_routes(root)
            or extract_fastapi_routes(root)
            or extract_express_routes(root)
        )

    manifests = []
    for name in (
        "package.json",
        "composer.json",
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "go.mod",
    ):
        if (root / name).exists():
            manifests.append(name)

    auth_controls = sorted(
        {
            name
            for route in routes
            for name in route.middleware
            if "auth" in name.lower()
        }
    )
    return {
        "framework": framework,
        "routes": [
            {
                "path": route.path,
                "methods": route.methods,
                "auth_required": route.auth_required,
                "middleware": route.middleware,
                "source_file": route.source_file,
            }
            for route in routes
        ],
        "auth_controls": auth_controls,
        "config_findings": [],
        "dependency_manifests": manifests,
        "source_locations": [str(root)],
    }


def compare_runtime_to_source(
    runtime_paths: list[str],
    source_routes: list[RepoRoute],
) -> list[dict[str, Any]]:
    """Correlate runtime endpoints to source routes (enrichment only)."""
    source_paths = {route.path for route in source_routes}
    rows: list[dict[str, Any]] = []
    for path in runtime_paths:
        # Normalize numeric/id segments loosely.
        normalized = re.sub(r"/\d+", "/{id}", path)
        matched = normalized in source_paths or path in source_paths
        route = next(
            (
                item
                for item in source_routes
                if item.path in {path, normalized}
            ),
            None,
        )
        rows.append(
            {
                "runtime_path": path,
                "source_route": route.path if route else None,
                "auth_middleware": list(route.middleware) if route else [],
                "correlated": matched,
                "evidence_source": "correlated",
            }
        )
    return rows
