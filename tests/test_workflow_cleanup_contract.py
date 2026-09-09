"""STEP 57 — workflow cleanup contract when mutate assertion fails."""

from __future__ import annotations

from magic_security.workflow_packs import _builtin_authz_write
from magic_security.workflow_schema import validate_workflows_for_run


def test_authz_workflow_requires_cleanup_and_disposable():
    workflow = _builtin_authz_write()
    assert any(step.phase == "cleanup" for step in workflow.steps)
    assert workflow.requires_disposable
    # Validation fails closed without disposable contexts
    try:
        validate_workflows_for_run(
            [workflow],
            auth_enabled=True,
            browser_enabled=False,
            disposable_contexts=[],
        )
        raised = False
    except Exception:
        raised = True
    assert raised
