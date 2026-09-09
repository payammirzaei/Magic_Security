"""Workflow packs for STEPs 34–37."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.workflow_runner import WorkflowExecutionRecord, WorkflowRunner
from magic_security.workflow_schema import (
    WorkflowDefinition,
    load_workflows,
    parse_workflow_dict,
    validate_workflows_for_run,
)


@dataclass
class WorkflowPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    executions: list[dict[str, Any]] = field(default_factory=list)


def _builtin_authz_write() -> WorkflowDefinition:
    return parse_workflow_dict(
        {
            "name": "authz_write_bola",
            "safety": "disposable_mutate",
            "requires_auth": True,
            "requires_disposable": True,
            "description": "User A creates disposable note; user B mutation attempt; cleanup",
            "steps": [
                {
                    "id": "create_note",
                    "phase": "create",
                    "method": "POST",
                    "path": "/api/notes",
                    "context": "user_a",
                    "creates_resource": True,
                    "body": {
                        "title": "magic-security-disposable",
                        "body": "canary-note",
                    },
                    "extract": [
                        {"name": "resource_id", "from": "json", "path": "id"}
                    ],
                    "assert": [{"type": "status", "value": 201}],
                },
                {
                    "id": "owner_read",
                    "phase": "read",
                    "method": "GET",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_a",
                    "assert": [{"type": "status", "value": 200}],
                },
                {
                    "id": "cross_mutate",
                    "phase": "mutate",
                    "method": "PUT",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_b",
                    "body": {"body": "hijacked"},
                    "assert": [{"type": "status_in", "value": [200, 401, 403]}],
                },
                {
                    "id": "verify_owner",
                    "phase": "verify",
                    "method": "GET",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_a",
                    "assert": [{"type": "status", "value": 200}],
                },
                {
                    "id": "cleanup_note",
                    "phase": "cleanup",
                    "method": "DELETE",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_a",
                    "cleanup_of": "create_note",
                    "assert": [{"type": "status_in", "value": [200, 204, 404]}],
                },
            ],
        }
    )


def _builtin_stored_xss() -> WorkflowDefinition:
    return parse_workflow_dict(
        {
            "name": "stored_xss_canary",
            "safety": "disposable_mutate",
            "requires_auth": True,
            "requires_browser": True,
            "requires_disposable": True,
            "steps": [
                {
                    "id": "store_canary",
                    "phase": "create",
                    "method": "POST",
                    "path": "/api/notes",
                    "context": "user_a",
                    "creates_resource": True,
                    "body": {
                        "title": "xss-canary",
                        "body": "<magic-security-canary id='msx'></magic-security-canary>",
                    },
                    "extract": [
                        {"name": "resource_id", "from": "json", "path": "id"}
                    ],
                    "assert": [{"type": "status", "value": 201}],
                },
                {
                    "id": "render_read",
                    "phase": "verify",
                    "method": "GET",
                    "path": "/notes/{{resource_id}}",
                    "context": "user_a",
                    "assert": [
                        {"type": "status", "value": 200},
                        {
                            "type": "body_contains",
                            "value": "magic-security-canary",
                        },
                    ],
                },
                {
                    "id": "cleanup_xss",
                    "phase": "cleanup",
                    "method": "DELETE",
                    "path": "/api/notes/{{resource_id}}",
                    "context": "user_a",
                    "cleanup_of": "store_canary",
                    "assert": [{"type": "status_in", "value": [200, 204, 404]}],
                },
            ],
        }
    )


def _builtin_upload() -> WorkflowDefinition:
    return parse_workflow_dict(
        {
            "name": "upload_security",
            "safety": "disposable_mutate",
            "requires_auth": True,
            "requires_disposable": True,
            "steps": [
                {
                    "id": "upload_txt",
                    "phase": "create",
                    "method": "POST",
                    "path": "/api/uploads",
                    "context": "user_a",
                    "creates_resource": True,
                    "headers": {"Content-Type": "text/plain"},
                    "body": "magic-security-upload-fixture",
                    "extract": [
                        {"name": "resource_id", "from": "json", "path": "id"}
                    ],
                    "assert": [{"type": "status", "value": 201}],
                },
                {
                    "id": "read_upload",
                    "phase": "read",
                    "method": "GET",
                    "path": "/api/uploads/{{resource_id}}",
                    "context": "user_a",
                    "assert": [{"type": "status", "value": 200}],
                },
                {
                    "id": "cross_read",
                    "phase": "verify",
                    "method": "GET",
                    "path": "/api/uploads/{{resource_id}}",
                    "context": "user_b",
                    "assert": [{"type": "status_in", "value": [200, 401, 403]}],
                },
                {
                    "id": "cleanup_upload",
                    "phase": "cleanup",
                    "method": "DELETE",
                    "path": "/api/uploads/{{resource_id}}",
                    "context": "user_a",
                    "cleanup_of": "upload_txt",
                    "assert": [{"type": "status_in", "value": [200, 204, 404]}],
                },
            ],
        }
    )


def _builtin_session() -> WorkflowDefinition:
    return parse_workflow_dict(
        {
            "name": "session_lifecycle",
            "safety": "auth_lifecycle",
            "requires_auth": True,
            "requires_disposable": False,
            "steps": [
                {
                    "id": "login",
                    "phase": "login",
                    "method": "POST",
                    "path": "/api/login",
                    "context": "anonymous",
                    "body": {"username": "A", "password": "demo"},
                    "extract": [
                        {
                            "name": "session_fingerprint",
                            "from": "header",
                            "header": "set-cookie",
                        }
                    ],
                    "assert": [{"type": "status_in", "value": [200, 204]}],
                },
                {
                    "id": "me",
                    "phase": "verify",
                    "method": "GET",
                    "path": "/api/me",
                    "context": "user_a",
                    "assert": [{"type": "status", "value": 200}],
                },
                {
                    "id": "logout",
                    "phase": "logout",
                    "method": "POST",
                    "path": "/api/logout",
                    "context": "user_a",
                    "assert": [{"type": "status_in", "value": [200, 204]}],
                },
            ],
        }
    )


def _finding_from_execution(
    execution: WorkflowExecutionRecord,
    *,
    check_id: str,
    title: str,
    kind: FindingKind,
    severity: Severity,
) -> Finding | None:
    if execution.ok and check_id.endswith("cleanup"):
        return None
    mutate = next(
        (step for step in execution.steps if step.phase == "mutate"),
        None,
    )
    if check_id == "workflow.authz.write" and mutate and mutate.status_code == 200:
        finding = Finding(
            title=title,
            severity=severity,
            kind=kind,
            url=mutate.path,
            description=(
                "Disposable write workflow observed cross-account mutation "
                "acceptance."
            ),
            evidence=(
                f"workflow={execution.workflow}; mutate_status="
                f"{mutate.status_code}; cleanup_ok="
                f"{execution.resources.get('all_cleaned')}. "
                "Raw resource IDs not stored."
            ),
            remediation="Enforce object-level auth on write/delete.",
            confidence=1.0 if execution.resources.get("all_cleaned") else 0.85,
            check_id=check_id,
            cwe="CWE-639",
        )
        attach_evidence(
            finding,
            EvidenceObject(
                check_id=check_id,
                proof_type="workflow_cross_account_mutate",
                baseline_summary="Owner created disposable object",
                mutation_summary="Peer context attempted mutation",
                observed_result=finding.evidence,
                confidence="verified" if finding.verified else "strong",
                sensitive_values_stored=False,
            ),
        )
        return finding

    if check_id == "workflow.stored_xss" and execution.ok:
        verify = next(
            (step for step in execution.steps if step.phase == "verify"),
            None,
        )
        if verify and verify.ok:
            finding = Finding(
                title=title,
                severity=severity,
                kind=kind,
                url=verify.path,
                description=(
                    "Stored canary markup was reflected at a render URL "
                    "and cleaned up."
                ),
                evidence=(
                    "Canary markup present in render response; "
                    f"cleanup_ok={execution.resources.get('all_cleaned')}. "
                    "No cookies extracted."
                ),
                remediation="Encode stored content on render.",
                confidence=0.9,
                check_id=check_id,
                cwe="CWE-79",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id=check_id,
                    proof_type="stored_canary_reflection",
                    baseline_summary="Stored harmless canary",
                    mutation_summary="Fetched render location",
                    observed_result=finding.evidence,
                    confidence="strong",
                    sensitive_values_stored=False,
                ),
            )
            return finding

    if check_id == "workflow.upload" and execution.ok:
        cross = next(
            (
                step
                for step in execution.steps
                if step.id == "cross_read"
            ),
            None,
        )
        if cross and cross.status_code == 200:
            finding = Finding(
                title=title,
                severity=Severity.MEDIUM,
                kind=FindingKind.EXPOSURE,
                url=cross.path,
                description="Uploaded disposable object readable cross-account.",
                evidence=(
                    f"cross_read_status=200; cleanup_ok="
                    f"{execution.resources.get('all_cleaned')}"
                ),
                remediation="Authorize access to uploaded objects.",
                confidence=0.95,
                check_id=check_id,
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id=check_id,
                    proof_type="upload_cross_account_read",
                    baseline_summary="Owner uploaded harmless fixture",
                    mutation_summary="Peer read attempt",
                    observed_result=finding.evidence,
                    confidence="verified",
                    sensitive_values_stored=False,
                ),
            )
            return finding

    if check_id == "workflow.session" and execution.ok:
        finding = Finding(
            title="Session lifecycle workflow completed",
            severity=Severity.INFO,
            kind=FindingKind.HARDENING,
            url="/api/login",
            description="Login/me/logout disposable lifecycle executed.",
            evidence=(
                "Session fingerprint captured from header metadata only; "
                "raw session values not stored in report variables."
            ),
            remediation="Invalidate sessions on logout and rotate tokens.",
            confidence=0.8,
            check_id=check_id,
        )
        attach_evidence(
            finding,
            EvidenceObject(
                check_id=check_id,
                proof_type="session_lifecycle_observation",
                baseline_summary="Login synthetic disposable account",
                mutation_summary="Logout then verify posture",
                observed_result=finding.evidence,
                confidence="likely",
                sensitive_values_stored=False,
            ),
        )
        return finding
    return None


async def run_workflow_packs(
    crawl: CrawlResult,
    contexts: list[AuthContext],
    *,
    workflow_path: str | None = None,
    browser: bool = False,
) -> WorkflowPackResult:
    result = WorkflowPackResult()
    disposable = [item.name for item in contexts if item.disposable]
    context_map = {item.name: item for item in contexts}

    builtins = [
        ("workflow.authz.write", "Cross-account write via disposable object", _builtin_authz_write),
        ("workflow.stored_xss", "Stored XSS canary reflection", _builtin_stored_xss),
        ("workflow.upload", "Upload cross-account exposure", _builtin_upload),
        ("workflow.session", "Session lifecycle", _builtin_session),
    ]

    workflows: list[tuple[str, str, WorkflowDefinition]] = []
    if workflow_path:
        for item in load_workflows(workflow_path):
            workflows.append((f"workflow.custom.{item.name}", item.name, item))
    else:
        # Built-ins only when disposable contexts exist (or session pack).
        for check_id, title, factory in builtins:
            workflows.append((check_id, title, factory()))

    exercised: list[str] = []
    skipped: list[str] = []

    for check_id, title, workflow in workflows:
        try:
            validate_workflows_for_run(
                [workflow],
                auth_enabled=bool(contexts),
                browser_enabled=browser,
                disposable_contexts=disposable
                if workflow.requires_disposable
                else [item.name for item in contexts],
            )
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"{workflow.name}:{exc}")
            continue

        # Map user_a/user_b aliases when disposable contexts exist.
        run_contexts = dict(context_map)
        if "user_a" not in run_contexts and len(contexts) >= 1:
            run_contexts["user_a"] = contexts[0]
        if "user_b" not in run_contexts and len(contexts) >= 2:
            run_contexts["user_b"] = contexts[1]

        if workflow.requires_browser and not browser:
            skipped.append(f"{workflow.name}:browser")
            continue

        runner = WorkflowRunner(target=crawl.target, contexts=run_contexts)
        execution = await runner.run(workflow)
        result.executions.append(execution.to_dict())
        exercised.append(workflow.name)

        kind = FindingKind.VULNERABILITY
        severity = Severity.HIGH
        if check_id.startswith("workflow.session"):
            kind = FindingKind.HARDENING
            severity = Severity.INFO
        if check_id.startswith("workflow.stored_xss"):
            severity = Severity.HIGH
        if check_id.startswith("workflow.upload"):
            kind = FindingKind.EXPOSURE
            severity = Severity.MEDIUM

        finding = _finding_from_execution(
            execution,
            check_id=check_id,
            title=title,
            kind=kind,
            severity=severity,
        )
        if finding is not None:
            result.findings.append(finding)

    result.coverage = {
        "pack": "workflows_v1",
        "exercised": exercised,
        "skipped": skipped,
        "executions": len(result.executions),
        "all_resources_cleaned": all(
            item.get("resources", {}).get("all_cleaned", True)
            for item in result.executions
        ),
    }
    return result
