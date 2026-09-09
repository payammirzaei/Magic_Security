"""Workflow runner and variable engine (STEP 32)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from magic_security.models import AuthContext
from magic_security.redaction import Redactor
from magic_security.transport import SecureTransport
from magic_security.workflow_resources import CleanupState, ResourceTracker
from magic_security.workflow_schema import (
    WorkflowAssertion,
    WorkflowDefinition,
    WorkflowSchemaError,
    WorkflowStep,
)


_TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


@dataclass
class StepExecutionRecord:
    step_id: str
    phase: str
    method: str
    path: str
    status_code: int | None = None
    ok: bool = False
    error: str | None = None
    assertions: list[dict[str, Any]] = field(default_factory=list)
    extracts: dict[str, Any] = field(default_factory=dict)
    response_len: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "phase": self.phase,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "ok": self.ok,
            "error": self.error,
            "assertions": self.assertions,
            "extracts": {
                key: ("<redacted>" if "token" in key.lower() or "session" in key.lower() else value)
                for key, value in self.extracts.items()
            },
            "response_len": self.response_len,
        }


@dataclass
class WorkflowExecutionRecord:
    workflow: str
    ok: bool = False
    cancelled: bool = False
    steps: list[StepExecutionRecord] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        redactor = Redactor()
        safe_vars = {
            key: (
                "<redacted>"
                if any(
                    token in key.lower()
                    for token in ("token", "session", "password", "secret")
                )
                else redactor.redact_text(str(value))[:120]
            )
            for key, value in self.variables.items()
        }
        return {
            "workflow": self.workflow,
            "ok": self.ok,
            "cancelled": self.cancelled,
            "error": self.error,
            "steps": [item.to_dict() for item in self.steps],
            "variables": safe_vars,
            "resources": self.resources,
        }


def render_template(value: str, variables: dict[str, Any]) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise WorkflowSchemaError(f"Unknown template variable: {name}")
        return str(variables[name])

    return _TEMPLATE_RE.sub(repl, value)


def _json_path(data: Any, path: str) -> Any:
    if not path:
        return data
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(path)
    return current


def _apply_extracts(
    step: WorkflowStep,
    response: httpx.Response,
    variables: dict[str, Any],
) -> dict[str, Any]:
    extracted: dict[str, Any] = {}
    for item in step.extracts:
        if item.from_ == "status":
            value: Any = response.status_code
        elif item.from_ == "body_len":
            value = len(response.content)
        elif item.from_ == "header":
            value = response.headers.get(item.header or item.path)
        elif item.from_ == "location":
            value = response.headers.get("location")
        elif item.from_ == "json":
            value = _json_path(response.json(), item.path)
        else:
            continue
        variables[item.name] = value
        extracted[item.name] = value
    return extracted


def _eval_assertion(
    assertion: WorkflowAssertion,
    response: httpx.Response,
    variables: dict[str, Any],
) -> tuple[bool, str]:
    try:
        if assertion.type == "status":
            ok = response.status_code == int(assertion.value)
            return ok, f"status={response.status_code} expected={assertion.value}"
        if assertion.type == "status_in":
            allowed = assertion.value if isinstance(assertion.value, list) else []
            ok = response.status_code in {int(item) for item in allowed}
            return ok, f"status={response.status_code} in={allowed}"
        if assertion.type == "json_equals":
            actual = _json_path(response.json(), assertion.path)
            ok = actual == assertion.value
            return ok, f"json.{assertion.path} equals check"
        if assertion.type == "json_exists":
            _json_path(response.json(), assertion.path)
            return True, f"json.{assertion.path} exists"
        if assertion.type == "header_equals":
            actual = response.headers.get(assertion.header)
            ok = actual == assertion.value
            return ok, f"header {assertion.header}"
        if assertion.type == "body_contains":
            ok = str(assertion.value) in response.text
            return ok, "body_contains"
        if assertion.type == "body_not_contains":
            ok = str(assertion.value) not in response.text
            return ok, "body_not_contains"
        if assertion.type == "variable_equals":
            ok = variables.get(assertion.variable) == assertion.value
            return ok, f"var {assertion.variable}"
        if assertion.type == "variable_exists":
            ok = assertion.variable in variables
            return ok, f"var {assertion.variable} exists"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    return False, f"unknown assertion {assertion.type}"


@dataclass
class WorkflowRunner:
    target: str
    contexts: dict[str, AuthContext]
    tracker: ResourceTracker = field(default_factory=ResourceTracker)
    cancelled: bool = False

    def cancel(self) -> None:
        self.cancelled = True

    async def run(self, workflow: WorkflowDefinition) -> WorkflowExecutionRecord:
        record = WorkflowExecutionRecord(workflow=workflow.name)
        variables = dict(workflow.variables)
        record.variables = variables

        try:
            for step in workflow.steps:
                if self.cancelled:
                    record.cancelled = True
                    record.error = "cancelled"
                    break
                step_record = await self._run_step(workflow, step, variables)
                record.steps.append(step_record)
                if not step_record.ok:
                    record.error = step_record.error or f"step {step.id} failed"
                    break
            else:
                record.ok = True
        finally:
            await self.cleanup(force=True)
            record.resources = self.tracker.to_dict()
            record.variables = dict(variables)
            if not self.tracker.all_cleaned() and workflow.may_mutate:
                record.ok = False
                record.error = record.error or "cleanup incomplete"
        return record

    async def _run_step(
        self,
        workflow: WorkflowDefinition,
        step: WorkflowStep,
        variables: dict[str, Any],
    ) -> StepExecutionRecord:
        record = StepExecutionRecord(
            step_id=step.id,
            phase=step.phase,
            method=step.method,
            path=step.path,
        )
        path = render_template(step.path, variables)
        url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
        headers = {
            key: render_template(value, variables)
            for key, value in step.headers.items()
        }
        body: Any = step.body
        if step.body_template is not None:
            rendered = render_template(step.body_template, variables)
            try:
                body = json.loads(rendered)
            except json.JSONDecodeError:
                body = rendered
        elif isinstance(body, str):
            body = render_template(body, variables)

        context = self.contexts.get(step.context)
        client_headers = dict(headers)
        cookies: dict[str, str] = {}
        if context is not None:
            client_headers.update(context.headers)
            cookies = dict(context.cookies)
        elif step.context != "anonymous":
            record.error = f"unknown context {step.context!r}"
            return record

        try:
            async with SecureTransport(
                follow_redirects=False,
                timeout=step.timeout_seconds,
                headers={
                    "User-Agent": "Magic-Security/1.1 workflow-runner",
                    "Accept": "application/json,*/*;q=0.5",
                    **client_headers,
                },
                cookies=cookies,
            ) as client:
                response = await client.request(
                    step.method,
                    url,
                    json=body if isinstance(body, (dict, list)) else None,
                    content=None if isinstance(body, (dict, list, type(None))) else body,
                )
        except Exception as exc:  # noqa: BLE001
            record.error = f"{type(exc).__name__}: {exc}"
            return record

        record.status_code = response.status_code
        record.response_len = len(response.content)
        try:
            extracted = _apply_extracts(step, response, variables)
            record.extracts = {
                key: value
                for key, value in extracted.items()
                if not any(
                    token in key.lower()
                    for token in ("token", "session", "password")
                )
            }
        except Exception as exc:  # noqa: BLE001
            record.error = f"extract failed: {exc}"
            return record

        if step.creates_resource or step.phase == "create":
            resource_id = variables.get("resource_id") or variables.get("id")
            cleanup_path = None
            for later in workflow.steps:
                if later.phase == "cleanup" and later.cleanup_of in {
                    step.id,
                    None,
                    "",
                }:
                    cleanup_path = later.path
                    break
            if resource_id is not None and cleanup_path:
                self.tracker.track(
                    resource_id=str(resource_id),
                    owning_context=step.context,
                    cleanup_path=cleanup_path,
                    cleanup_method=next(
                        (
                            later.method
                            for later in workflow.steps
                            if later.phase == "cleanup"
                        ),
                        "DELETE",
                    ),
                    workflow_name=workflow.name,
                    step_id=step.id,
                )

        assertion_results: list[dict[str, Any]] = []
        for assertion in step.assertions:
            ok, detail = _eval_assertion(assertion, response, variables)
            assertion_results.append(
                {"type": assertion.type, "ok": ok, "detail": detail}
            )
            if not ok:
                record.assertions = assertion_results
                record.error = f"assertion failed: {detail}"
                return record
        record.assertions = assertion_results

        if step.phase == "cleanup":
            for item in self.tracker.pending():
                item.state = CleanupState.CLEANED
                item.detail = f"cleanup step {step.id} status={response.status_code}"

        record.ok = True
        return record

    async def cleanup(self, *, force: bool = False) -> None:
        pending = list(self.tracker.pending())
        if not pending:
            return
        for item in pending:
            path = render_template(
                item.cleanup_path,
                {"resource_id": item.resource_id, "id": item.resource_id},
            )
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            context = self.contexts.get(item.owning_context)
            headers = {}
            cookies: dict[str, str] = {}
            if context is not None:
                headers = dict(context.headers)
                cookies = dict(context.cookies)
            try:
                async with SecureTransport(
                    follow_redirects=False,
                    timeout=5.0,
                    headers=headers,
                    cookies=cookies,
                ) as client:
                    response = await client.request(item.cleanup_method, url)
                if response.status_code < 500:
                    item.state = CleanupState.CLEANED
                    item.detail = f"HTTP {response.status_code}"
                else:
                    item.state = CleanupState.FAILED
                    item.detail = f"HTTP {response.status_code}"
            except Exception as exc:  # noqa: BLE001
                item.state = CleanupState.FAILED
                item.detail = type(exc).__name__
                if not force:
                    raise
