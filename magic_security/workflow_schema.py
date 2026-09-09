"""Declarative workflow schema + validator (STEP 31).

Unsafe or invalid definitions fail before any network activity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class WorkflowSchemaError(ValueError):
    """Raised when a workflow definition is invalid or unsafe."""


_ALLOWED_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)
_ALLOWED_SAFETY = frozenset(
    {
        "read_only",
        "disposable_mutate",
        "auth_lifecycle",
        "cleanup",
    }
)
_ALLOWED_EXTRACT_FROM = frozenset(
    {"json", "header", "location", "status", "body_len"}
)
_ALLOWED_ASSERT_TYPES = frozenset(
    {
        "status",
        "status_in",
        "json_equals",
        "json_exists",
        "header_equals",
        "body_contains",
        "body_not_contains",
        "variable_equals",
        "variable_exists",
    }
)
_PHASES = ("create", "read", "mutate", "verify", "cleanup", "login", "logout")
_FORBIDDEN_BODY_TOKENS = (
    "<?php",
    "<%",
    "<script src=",
    "javascript:alert(document.cookie)",
    "file://",
)


@dataclass(frozen=True, slots=True)
class WorkflowExtract:
    name: str
    from_: str
    path: str = ""
    header: str = ""


@dataclass(frozen=True, slots=True)
class WorkflowAssertion:
    type: str
    value: Any = None
    path: str = ""
    header: str = ""
    variable: str = ""


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    id: str
    phase: str
    method: str
    path: str
    context: str = "anonymous"
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    body_template: str | None = None
    extracts: tuple[WorkflowExtract, ...] = ()
    assertions: tuple[WorkflowAssertion, ...] = ()
    timeout_seconds: float = 5.0
    creates_resource: bool = False
    cleanup_of: str | None = None


@dataclass(frozen=True, slots=True)
class WorkflowDefinition:
    name: str
    safety: str
    description: str = ""
    requires_auth: bool = False
    requires_browser: bool = False
    requires_disposable: bool = True
    variables: dict[str, Any] = field(default_factory=dict)
    steps: tuple[WorkflowStep, ...] = ()
    source_path: str | None = None

    @property
    def may_mutate(self) -> bool:
        return self.safety in {"disposable_mutate", "auth_lifecycle"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise WorkflowSchemaError(message)


def _parse_extract(raw: dict[str, Any], step_id: str) -> WorkflowExtract:
    name = str(raw.get("name") or "").strip()
    from_ = str(raw.get("from") or raw.get("from_") or "").strip()
    _require(bool(name), f"step {step_id}: extract needs name")
    _require(
        from_ in _ALLOWED_EXTRACT_FROM,
        f"step {step_id}: extract.from must be one of {sorted(_ALLOWED_EXTRACT_FROM)}",
    )
    return WorkflowExtract(
        name=name,
        from_=from_,
        path=str(raw.get("path") or ""),
        header=str(raw.get("header") or ""),
    )


def _parse_assertion(raw: dict[str, Any], step_id: str) -> WorkflowAssertion:
    type_ = str(raw.get("type") or "").strip()
    _require(
        type_ in _ALLOWED_ASSERT_TYPES,
        f"step {step_id}: assertion.type must be one of {sorted(_ALLOWED_ASSERT_TYPES)}",
    )
    return WorkflowAssertion(
        type=type_,
        value=raw.get("value"),
        path=str(raw.get("path") or ""),
        header=str(raw.get("header") or ""),
        variable=str(raw.get("variable") or ""),
    )


def _parse_step(raw: dict[str, Any], index: int) -> WorkflowStep:
    _require(isinstance(raw, dict), f"step[{index}] must be an object")
    step_id = str(raw.get("id") or f"step_{index}").strip()
    phase = str(raw.get("phase") or "").strip()
    method = str(raw.get("method") or "GET").strip().upper()
    path = str(raw.get("path") or "").strip()
    _require(bool(path), f"step {step_id}: path is required")
    _require(
        phase in _PHASES,
        f"step {step_id}: phase must be one of {list(_PHASES)}",
    )
    _require(
        method in _ALLOWED_METHODS,
        f"step {step_id}: method {method!r} not allowed",
    )
    _require(
        path.startswith("/"),
        f"step {step_id}: path must be relative (start with /)",
    )
    _require(
        "://" not in path,
        f"step {step_id}: absolute URLs are not allowed in workflow paths",
    )

    headers = raw.get("headers") or {}
    _require(isinstance(headers, dict), f"step {step_id}: headers must be object")

    extracts_raw = raw.get("extract") or raw.get("extracts") or []
    _require(isinstance(extracts_raw, list), f"step {step_id}: extract must be list")
    extracts = tuple(_parse_extract(item, step_id) for item in extracts_raw)

    assertions_raw = raw.get("assert") or raw.get("assertions") or []
    _require(
        isinstance(assertions_raw, list),
        f"step {step_id}: assert must be list",
    )
    assertions = tuple(
        _parse_assertion(item, step_id) for item in assertions_raw
    )

    body = raw.get("body")
    body_template = raw.get("body_template")
    if isinstance(body, str):
        lowered = body.lower()
        for token in _FORBIDDEN_BODY_TOKENS:
            _require(
                token not in lowered,
                f"step {step_id}: body contains forbidden safety token",
            )
    if isinstance(body_template, str):
        lowered = body_template.lower()
        for token in _FORBIDDEN_BODY_TOKENS:
            _require(
                token not in lowered,
                f"step {step_id}: body_template contains forbidden safety token",
            )

    timeout = float(raw.get("timeout_seconds") or 5.0)
    _require(0.5 <= timeout <= 30.0, f"step {step_id}: timeout out of range")

    return WorkflowStep(
        id=step_id,
        phase=phase,
        method=method,
        path=path,
        context=str(raw.get("context") or "anonymous"),
        headers={str(k): str(v) for k, v in headers.items()},
        body=body,
        body_template=str(body_template) if body_template is not None else None,
        extracts=extracts,
        assertions=assertions,
        timeout_seconds=timeout,
        creates_resource=bool(raw.get("creates_resource")),
        cleanup_of=(
            str(raw["cleanup_of"])
            if raw.get("cleanup_of") is not None
            else None
        ),
    )


def parse_workflow_dict(
    data: dict[str, Any],
    *,
    source_path: str | None = None,
) -> WorkflowDefinition:
    _require(isinstance(data, dict), "workflow root must be an object")
    name = str(data.get("name") or "").strip()
    safety = str(data.get("safety") or "").strip()
    _require(bool(name), "workflow.name is required")
    _require(
        safety in _ALLOWED_SAFETY,
        f"workflow.safety must be one of {sorted(_ALLOWED_SAFETY)}",
    )

    steps_raw = data.get("steps")
    if steps_raw is None:
        # Shorthand phase maps: create/read/mutate/verify/cleanup
        steps_raw = []
        for phase in _PHASES:
            block = data.get(phase)
            if block is None:
                continue
            if isinstance(block, dict):
                item = dict(block)
                item.setdefault("phase", phase)
                item.setdefault("id", f"{phase}_0")
                steps_raw.append(item)
            elif isinstance(block, list):
                for index, entry in enumerate(block):
                    _require(isinstance(entry, dict), f"{phase}[{index}] must be object")
                    item = dict(entry)
                    item.setdefault("phase", phase)
                    item.setdefault("id", f"{phase}_{index}")
                    steps_raw.append(item)
            else:
                raise WorkflowSchemaError(f"{phase} must be object or list")

    _require(isinstance(steps_raw, list) and steps_raw, "workflow needs steps")
    steps = tuple(_parse_step(item, index) for index, item in enumerate(steps_raw))

    if safety == "read_only":
        for step in steps:
            _require(
                step.method in {"GET", "HEAD", "OPTIONS"},
                f"read_only workflow cannot use {step.method} ({step.id})",
            )
    if safety == "disposable_mutate":
        has_cleanup = any(step.phase == "cleanup" for step in steps)
        _require(has_cleanup, "disposable_mutate workflows require a cleanup phase")
        has_create = any(step.creates_resource or step.phase == "create" for step in steps)
        _require(has_create, "disposable_mutate workflows require a create step")

    variables = data.get("variables") or {}
    _require(isinstance(variables, dict), "variables must be an object")

    return WorkflowDefinition(
        name=name,
        safety=safety,
        description=str(data.get("description") or ""),
        requires_auth=bool(data.get("requires_auth")),
        requires_browser=bool(data.get("requires_browser")),
        requires_disposable=bool(data.get("requires_disposable", True)),
        variables={str(k): v for k, v in variables.items()},
        steps=steps,
        source_path=source_path,
    )


def load_workflow_file(path: str | Path) -> WorkflowDefinition:
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise WorkflowSchemaError(f"Cannot read workflow: {source}") from exc

    suffix = source.suffix.lower()
    data: Any
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise WorkflowSchemaError(
                "PyYAML is required to load .yaml workflows"
            ) from exc
        try:
            data = yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            raise WorkflowSchemaError(f"Invalid YAML in {source}") from exc
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise WorkflowSchemaError(f"Invalid JSON in {source}") from exc

    if not isinstance(data, dict):
        raise WorkflowSchemaError("Workflow file root must be an object")
    return parse_workflow_dict(data, source_path=str(source))


def load_workflows(path: str | Path) -> list[WorkflowDefinition]:
    """Load a single workflow file or a directory of workflow files."""
    source = Path(path)
    if source.is_dir():
        files = sorted(
            [
                *source.glob("*.json"),
                *source.glob("*.yaml"),
                *source.glob("*.yml"),
            ]
        )
        _require(bool(files), f"No workflow files in {source}")
        return [load_workflow_file(item) for item in files]
    return [load_workflow_file(source)]


def validate_workflows_for_run(
    workflows: list[WorkflowDefinition],
    *,
    auth_enabled: bool,
    browser_enabled: bool,
    disposable_contexts: list[str],
) -> None:
    """Fail closed before network if runtime prerequisites are missing."""
    for workflow in workflows:
        if workflow.requires_auth and not auth_enabled:
            raise WorkflowSchemaError(
                f"Workflow {workflow.name!r} requires auth contexts"
            )
        if workflow.requires_browser and not browser_enabled:
            raise WorkflowSchemaError(
                f"Workflow {workflow.name!r} requires --browser"
            )
        if workflow.requires_disposable and workflow.may_mutate:
            if not disposable_contexts:
                raise WorkflowSchemaError(
                    f"Workflow {workflow.name!r} requires disposable=true "
                    "auth contexts"
                )
        for step in workflow.steps:
            if step.context not in {"anonymous", *disposable_contexts}:
                # Non-disposable named contexts are allowed for read-only.
                if workflow.may_mutate and step.context != "anonymous":
                    if step.context not in disposable_contexts:
                        raise WorkflowSchemaError(
                            f"Workflow {workflow.name!r} step {step.id} "
                            f"uses non-disposable context {step.context!r}"
                        )
