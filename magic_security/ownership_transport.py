"""Dedicated ownership-verification transport (well-known challenge fetch)."""

from __future__ import annotations

from urllib.parse import urlparse

from magic_security.budgets import RequestBudget
from magic_security.config import BudgetConfig, RateConfig, ScanConfig, ScopeConfig
from magic_security.context import create_scan_context
from magic_security.scope import ScopePolicy
from magic_security.transport import (
    ScopeBlockedError,
    attach_rate_limiter,
    open_secure_transport,
)

WELL_KNOWN_PATH = "/.well-known/magic-security-verification.txt"
_MAX_WELL_KNOWN_BYTES = 4096


class OwnershipTransportError(RuntimeError):
    pass


def _ownership_scan_context(base_url: str):
    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise OwnershipTransportError("base_url needs a host")
    origin = f"{parsed.scheme or 'https'}://{host}"
    if parsed.port:
        origin = f"{origin}:{parsed.port}"

    config = ScanConfig(
        target=origin + "/",
        allow_remote=True,
        max_pages=1,
        scope=ScopeConfig(
            loopback_only=False,
            allowed_hosts=(host,),
            same_origin=True,
            deny_external_redirects=True,
            denied_paths=(),
        ),
        budgets=BudgetConfig(
            max_total_requests=2,
            max_requests_per_endpoint=2,
            max_response_bytes=_MAX_WELL_KNOWN_BYTES,
            max_redirects=0,
            max_pages=1,
            max_active_mutations=0,
        ),
        rate=RateConfig(requests_per_second=2.0, global_concurrency=1),
    )
    ctx = create_scan_context(config)
    ctx.scope = ScopePolicy(config.scope, target=config.target, allow_remote=True)
    ctx.budgets = RequestBudget(config.budgets)
    attach_rate_limiter(ctx, config.rate)
    return ctx, origin


async def fetch_well_known_verification(base_url: str) -> str:
    """GET /.well-known/magic-security-verification.txt with isolated safety controls.

    - No automatic redirects (max_redirects=0 / follow_redirects=False)
    - Host allowlisted to the ownership target only
    - Hard 4 KiB response cap enforced during streaming
    """
    ctx, origin = _ownership_scan_context(base_url)
    url = origin.rstrip("/") + WELL_KNOWN_PATH
    path = urlparse(url).path or ""
    if path != WELL_KNOWN_PATH:
        raise OwnershipTransportError("refusing non well-known path")

    try:
        async with open_secure_transport(
            ctx,
            follow_redirects=False,
            timeout=5.0,
            max_response_bytes=_MAX_WELL_KNOWN_BYTES,
            max_redirects=0,
        ) as client:
            response = await client.get(url)
    except ScopeBlockedError as exc:
        raise OwnershipTransportError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise OwnershipTransportError(f"well-known fetch failed: {exc}") from exc

    if response.status_code != 200:
        raise OwnershipTransportError(
            f"well-known HTTP {response.status_code}"
        )
    text = response.text
    if len(text.encode("utf-8", errors="replace")) > _MAX_WELL_KNOWN_BYTES:
        raise OwnershipTransportError("well-known body too large")
    return text
