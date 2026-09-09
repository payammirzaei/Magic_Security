"""Disposable resource lifecycle and cleanup (STEP 33)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CleanupState(str, Enum):
    PENDING = "pending"
    CLEANED = "cleaned"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TrackedResource:
    resource_id: str
    fingerprint: str
    owning_context: str
    cleanup_path: str
    cleanup_method: str = "DELETE"
    workflow_name: str = ""
    step_id: str = ""
    state: CleanupState = CleanupState.PENDING
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id_fingerprint": self.fingerprint,
            "owning_context": self.owning_context,
            "cleanup_path": self.cleanup_path,
            "cleanup_method": self.cleanup_method,
            "workflow_name": self.workflow_name,
            "step_id": self.step_id,
            "state": self.state.value,
            "detail": self.detail,
        }


def resource_fingerprint(resource_id: str) -> str:
    return hashlib.sha256(resource_id.encode("utf-8")).hexdigest()[:16]


@dataclass
class ResourceTracker:
    resources: list[TrackedResource] = field(default_factory=list)

    def track(
        self,
        *,
        resource_id: str,
        owning_context: str,
        cleanup_path: str,
        cleanup_method: str = "DELETE",
        workflow_name: str = "",
        step_id: str = "",
    ) -> TrackedResource:
        item = TrackedResource(
            resource_id=resource_id,
            fingerprint=resource_fingerprint(resource_id),
            owning_context=owning_context,
            cleanup_path=cleanup_path,
            cleanup_method=cleanup_method.upper(),
            workflow_name=workflow_name,
            step_id=step_id,
        )
        self.resources.append(item)
        return item

    def pending(self) -> list[TrackedResource]:
        return [
            item
            for item in self.resources
            if item.state is CleanupState.PENDING
        ]

    def all_cleaned(self) -> bool:
        return all(
            item.state in {CleanupState.CLEANED, CleanupState.SKIPPED}
            for item in self.resources
        ) if self.resources else True

    def to_dict(self) -> dict[str, Any]:
        return {
            "resources": [item.to_dict() for item in self.resources],
            "pending": len(self.pending()),
            "all_cleaned": self.all_cleaned(),
        }
