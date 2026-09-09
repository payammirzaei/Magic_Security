"""Central HTTP transport (STEP 9 / STEP 51 network safety)."""

from __future__ import annotations

import asyncio
import contextvars
import uuid
from types import TracebackType
from typing import Any
from urllib.parse import urlparse

import httpx

from magic_security.budgets import RequestBudget
from magic_security.config import RateConfig
from magic_security.rate_limit import RateLimiter
from magic_security.scope import ScopePolicy

DEFAULT_USER_AGENT = "Magic-Security/1.1 local-security-scanner"

_SCAN_CONTEXT: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "magic_security_scan_context",
    default=None,
)


class ScopeBlockedError(httpx.RequestError):
    def __init__(self, url: str, reason: str) -> None:
        request = httpx.Request("GET", url)
        super().__init__(
            f"Request blocked by scope ({reason}): {url}",
            request=request,
        )
        self.url = url
        self.reason = reason


class BudgetBlockedError(httpx.RequestError):
    def __init__(self, url: str) -> None:
        request = httpx.Request("GET", url)
        super().__init__(f"Request blocked by budget: {url}", request=request)
        self.url = url


def bind_scan_context(scan_context: Any) -> contextvars.Token:
    """Bind ScanContext for the current async task / call stack."""
    return _SCAN_CONTEXT.set(scan_context)


def reset_scan_context(token: contextvars.Token) -> None:
    _SCAN_CONTEXT.reset(token)


def current_scan_context(
    scan_context: Any | None = None,
    crawl: Any | None = None,
) -> Any:
    """Resolve ScanContext from explicit arg, crawl attachment, or bound context."""
    if scan_context is not None:
        return scan_context
    if crawl is not None:
        attached = getattr(crawl, "scan_context", None)
        if attached is not None:
            return attached
    bound = _SCAN_CONTEXT.get()
    if bound is None:
        raise RuntimeError(
            "No ScanContext for network I/O. Pass scan_context=, attach "
            "crawl.scan_context, or bind_scan_context() in the engine."
        )
    return bound


def open_secure_transport(
    scan_context: Any | None = None,
    *,
    crawl: Any | None = None,
    **kwargs: Any,
) -> SecureTransport:
    """Fail-closed factory: every outbound HTTP client inherits safety controls."""
    ctx = current_scan_context(scan_context, crawl)
    if getattr(ctx, "scope", None) is None:
        raise RuntimeError("ScanContext.scope is required for network I/O")
    kwargs.pop("scan_context", None)
    return SecureTransport(scan_context=ctx, **kwargs)


def assert_url_in_scope(
    url: str,
    scan_context: Any | None = None,
    *,
    crawl: Any | None = None,
    for_redirect: bool = False,
) -> None:
    """Browser / WebSocket gate: block out-of-scope URLs before navigation."""
    ctx = current_scan_context(scan_context, crawl)
    scope = getattr(ctx, "scope", None)
    if scope is None:
        raise RuntimeError("ScanContext.scope is required for navigation")
    decision = scope.decide(url, for_redirect=for_redirect)
    if not decision.allowed:
        raise ScopeBlockedError(url, decision.reason)


class SecureTransport:
    """httpx wrapper that enforces scope, budgets, and rate limits."""

    def __init__(
        self,
        *,
        follow_redirects: bool = False,
        timeout: float = 8.0,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        scope: ScopePolicy | None = None,
        budgets: RequestBudget | None = None,
        rate_limiter: RateLimiter | None = None,
        scan_context: Any = None,
        max_response_bytes: int | None = None,
    ) -> None:
        self.follow_redirects = follow_redirects
        self.timeout = timeout
        merged = {"User-Agent": DEFAULT_USER_AGENT}
        if headers:
            merged.update(headers)
        self.headers = merged
        self.cookies = cookies or {}
        self.scope = scope or getattr(scan_context, "scope", None)
        self.budgets = budgets or getattr(scan_context, "budgets", None)
        self.rate_limiter = rate_limiter or getattr(
            scan_context,
            "rate_limiter",
            None,
        )
        self.scan_context = scan_context
        self.max_response_bytes = max_response_bytes
        self._client: httpx.AsyncClient | None = None
        self.last_request_id: str | None = None
        self.last_metadata: dict[str, Any] = {}

    async def __aenter__(self) -> SecureTransport:
        self._client = httpx.AsyncClient(
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
            headers=self.headers,
            cookies=self.cookies,
        )
        await self._client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._client is not None:
            await self._client.__aexit__(exc_type, exc, tb)
            self._client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError(
                "SecureTransport must be used as an async context manager"
            )
        return self._client

    def _cancelled(self) -> bool:
        if self.scan_context is None:
            return False
        checker = getattr(self.scan_context, "is_cancelled", None)
        return bool(checker and checker())

    async def _before_request(
        self,
        method: str,
        url: str,
        *,
        mutation: bool = False,
        for_redirect: bool = False,
    ) -> str:
        if self._cancelled():
            raise asyncio.CancelledError("scan cancelled")

        if self.scope is not None:
            decision = self.scope.decide(url, for_redirect=for_redirect)
            if not decision.allowed:
                raise ScopeBlockedError(url, decision.reason)

        if self.budgets is not None and not self.budgets.consume_request(
            url,
            mutation=mutation,
        ):
            raise BudgetBlockedError(url)

        host = urlparse(url).hostname or ""
        if self.rate_limiter is not None:
            await self.rate_limiter.acquire(
                host,
                cancelled=self._cancelled,
            )

        request_id = uuid.uuid4().hex[:12]
        self.last_request_id = request_id
        self.last_metadata = {
            "request_id": request_id,
            "method": method.upper(),
            "url": url,
            "host": host,
        }
        metrics = getattr(self.scan_context, "metrics", None)
        if metrics is not None:
            metrics.requests += 1
        return host

    async def _after_request(
        self,
        host: str,
        response: httpx.Response,
    ) -> httpx.Response:
        if self.rate_limiter is not None:
            try:
                if self.rate_limiter.should_backoff(response.status_code):
                    await self.rate_limiter.backoff(response.status_code)
            finally:
                self.rate_limiter.release(host)

        limit = self.max_response_bytes
        if limit is None and self.budgets is not None:
            limit = self.budgets.config.max_response_bytes
        if limit is not None and len(response.content) > limit:
            self.last_metadata["truncated"] = True
            self.last_metadata["response_bytes"] = len(response.content)
        return response

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        host = await self._before_request("GET", url, mutation=False)
        try:
            response = await self._ensure_client().get(url, **kwargs)
        except Exception:
            if self.rate_limiter is not None:
                self.rate_limiter.release(host)
            raise
        return await self._after_request(host, response)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        host = await self._before_request("POST", url, mutation=True)
        try:
            response = await self._ensure_client().post(url, **kwargs)
        except Exception:
            if self.rate_limiter is not None:
                self.rate_limiter.release(host)
            raise
        return await self._after_request(host, response)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        host = await self._before_request("HEAD", url, mutation=False)
        try:
            response = await self._ensure_client().head(url, **kwargs)
        except Exception:
            if self.rate_limiter is not None:
                self.rate_limiter.release(host)
            raise
        return await self._after_request(host, response)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        host = await self._before_request("OPTIONS", url, mutation=False)
        try:
            response = await self._ensure_client().options(url, **kwargs)
        except Exception:
            if self.rate_limiter is not None:
                self.rate_limiter.release(host)
            raise
        return await self._after_request(host, response)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        mutation = method.upper() not in {"GET", "HEAD", "OPTIONS", "TRACE"}
        host = await self._before_request(method, url, mutation=mutation)
        try:
            response = await self._ensure_client().request(method, url, **kwargs)
        except Exception:
            if self.rate_limiter is not None:
                self.rate_limiter.release(host)
            raise
        return await self._after_request(host, response)

    def stream(self, method: str, url: str, **kwargs: Any):
        client = self._ensure_client()

        class _ScopedStream:
            def __init__(self, transport: SecureTransport) -> None:
                self._transport = transport
                self._cm = None
                self._host = ""

            async def __aenter__(self):
                self._host = await self._transport._before_request(
                    method,
                    url,
                    mutation=method.upper() not in {"GET", "HEAD"},
                )
                self._cm = client.stream(method, url, **kwargs)
                return await self._cm.__aenter__()

            async def __aexit__(self, *args):
                if self._transport.rate_limiter is not None:
                    self._transport.rate_limiter.release(self._host)
                if self._cm is not None:
                    return await self._cm.__aexit__(*args)
                return None

        return _ScopedStream(self)


def attach_rate_limiter(
    scan_context: Any,
    rate: RateConfig | None = None,
) -> RateLimiter:
    from magic_security.config import RateConfig as RC

    cfg = rate
    if cfg is None:
        config = getattr(scan_context, "config", None)
        cfg = getattr(config, "rate", None) if config is not None else None
    limiter = RateLimiter(cfg or RC())
    scan_context.rate_limiter = limiter
    return limiter
