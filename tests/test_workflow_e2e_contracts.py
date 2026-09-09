"""STEP 57 — workflow pack unit/integration contracts."""

from __future__ import annotations

import pytest

from magic_security.workflow_packs import (
    _builtin_authz_write,
    _builtin_session,
    _builtin_stored_xss,
    _builtin_upload,
)
from magic_security.workflow_schema import WorkflowSchemaError, parse_workflow_dict


def test_builtin_workflows_exist():
    builtins = [
        _builtin_authz_write(),
        _builtin_stored_xss(),
        _builtin_upload(),
        _builtin_session(),
    ]
    assert len(builtins) == 4
    for wf in builtins:
        assert wf.name
        assert wf.steps
        assert any(step.phase == "cleanup" for step in wf.steps) or wf.name == "session_lifecycle"


def test_unsafe_payment_workflow_rejected():
    with pytest.raises(WorkflowSchemaError):
        parse_workflow_dict(
            {
                "name": "bad",
                "safety": "read_only",
                "steps": [
                    {
                        "id": "pay",
                        "phase": "mutate",
                        "method": "POST",
                        "path": "/pay",
                        "json": {"card": "4111111111111111"},
                    }
                ],
            }
        )
