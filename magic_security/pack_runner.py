"""Pack/check isolation and failure containment (STEP 14)."""

from __future__ import annotations

import asyncio
import traceback
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from magic_security.models import Finding
from magic_security.registry import CheckRegistry, CheckStatus


@dataclass
class PackFailure:
    pack: str
    check_id: str
    error_type: str
    message: str
    traceback: str = ""


@dataclass
class PackRunResult:
    findings: list[Finding] = field(default_factory=list)
    failures: list[PackFailure] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


async def run_isolated(
    *,
    pack: str,
    check_id: str,
    coro_factory: Callable[[], Awaitable[list[Finding]]],
    timeout: float = 60.0,
    registry: CheckRegistry | None = None,
) -> PackRunResult:
    result = PackRunResult()
    try:
        findings = await asyncio.wait_for(coro_factory(), timeout=timeout)
        result.findings.extend(findings)
        result.executed.append(check_id)
        if registry is not None:
            registry.record_execution(check_id, CheckStatus.EXECUTED)
    except asyncio.TimeoutError:
        failure = PackFailure(
            pack=pack,
            check_id=check_id,
            error_type="TimeoutError",
            message=f"check timed out after {timeout}s",
        )
        result.failures.append(failure)
        if registry is not None:
            registry.record_execution(
                check_id,
                CheckStatus.FAILED,
                failure.message,
            )
    except Exception as exc:  # noqa: BLE001 - isolation boundary
        failure = PackFailure(
            pack=pack,
            check_id=check_id,
            error_type=type(exc).__name__,
            message=str(exc),
            traceback=traceback.format_exc(limit=8),
        )
        result.failures.append(failure)
        if registry is not None:
            registry.record_execution(
                check_id,
                CheckStatus.FAILED,
                f"{failure.error_type}: {failure.message}",
            )
    return result


async def run_pack_safely(
    *,
    pack: str,
    operations: list[tuple[str, Callable[[], Awaitable[list[Finding]]]]],
    registry: CheckRegistry | None = None,
    timeout: float = 60.0,
) -> PackRunResult:
    combined = PackRunResult()
    for check_id, factory in operations:
        part = await run_isolated(
            pack=pack,
            check_id=check_id,
            coro_factory=factory,
            timeout=timeout,
            registry=registry,
        )
        combined.findings.extend(part.findings)
        combined.failures.extend(part.failures)
        combined.executed.extend(part.executed)
        combined.skipped.extend(part.skipped)
    return combined
