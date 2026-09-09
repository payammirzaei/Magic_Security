"""Central HTTP transport (STEP 9 / network safety hardening)."""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import socket
import uuid
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlparse

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

_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})

# Captured at import so unit tests that monkeypatch AsyncClient.get/post/request
# still work, while production keeps streaming size enforcement.
_ORIGINAL_GET = httpx.AsyncClient.get
_ORIGINAL_POST = httpx.AsyncClient.post
_ORIGINAL_HEAD = httpx.AsyncClient.head
_ORIGINAL_OPTIONS = httpx.AsyncClient.options
_ORIGINAL_REQUEST = httpx.AsyncClient.request
_ORIGINAL_STREAM = httpx.AsyncClient.stream


def _client_methods_monkeypatched() -> bool:
    return (
        httpx.AsyncClient.get is not _ORIGINAL_GET
        or httpx.AsyncClient.post is not _ORIGINAL_POST
        or httpx.AsyncClient.head is not _ORIGINAL_HEAD
        or httpx.AsyncClient.options is not _ORIGINAL_OPTIONS
        or httpx.AsyncClient.request is not _ORIGINAL_REQUEST
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


class ResponseTooLargeError(httpx.RequestError):
    def __init__(self, url: str, limit: int) -> None:
        request = httpx.Request("GET", url)
        super().__init__(
            f"Response exceeded max_response_bytes ({limit}): {url}",
            request=request,
        )
        self.url = url
        self.limit = limit


class TooManyRedirectsError(httpx.RequestError):
    def __init__(self, url: str, hops: int) -> None:
        request = httpx.Request("GET", url)
        super().__init__(
            f"Too many redirects ({hops}) starting from {url}",
            request=request,
        )
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


def resolve_host_addresses(host: str) -> frozenset[str]:
    """Resolve hostname to IP strings; empty on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return frozenset()
    return frozenset(str(item[4][0]) for item in infos)


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class SecureTransport:
    """httpx wrapper that enforces scope, budgets, rate limits, and DNS pins.

    Redirects are never followed by httpx. When follow_redirects=True, this
    class manually follows Location hops after a fresh scope check per hop.
    """

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
        max_redirects: int | None = None,
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
        if max_redirects is not None:
            self.max_redirects = max_redirects
        elif self.budgets is not None:
            self.max_redirects = self.budgets.config.max_redirects
        else:
            self.max_redirects = 10
        self._client: httpx.AsyncClient | None = None
        self.last_request_id: str | None = None
        self.last_metadata: dict[str, Any] = {}

    async def __aenter__(self) -> SecureTransport:
        # Never let httpx auto-follow — redirects are scope-checked manually.
        self._client = httpx.AsyncClient(
            follow_redirects=False,
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

    def _response_limit(self) -> int | None:
        if self.max_response_bytes is not None:
            return self.max_response_bytes
        if self.budgets is not None:
            return self.budgets.config.max_response_bytes
        return None

    def _dns_pins(self) -> dict[str, frozenset[str]] | None:
        if self.scan_context is None:
            return None
        pins = getattr(self.scan_context, "dns_pins", None)
        if pins is None:
            pins = {}
            setattr(self.scan_context, "dns_pins", pins)
        return pins

    def _enforce_dns_pin(self, url: str) -> frozenset[str] | None:
        """Resolve host, validate addresses, detect rebinding TOCTOU."""
        host = urlparse(url).hostname
        if not host:
            raise ScopeBlockedError(url, "missing_host")
        if _host_is_ip(host):
            return frozenset({host})

        addresses = resolve_host_addresses(host)
        if not addresses:
            raise ScopeBlockedError(url, "dns_resolution_failed")

        loopback_only = False
        allow_remote = False
        if self.scope is not None:
            loopback_only = bool(self.scope.config.loopback_only)
            allow_remote = bool(self.scope.allow_remote)
        if loopback_only and not allow_remote:
            for address in addresses:
                try:
                    if not ipaddress.ip_address(address).is_loopback:
                        raise ScopeBlockedError(url, "dns_resolved_non_loopback")
                except ValueError as exc:
                    raise ScopeBlockedError(url, "dns_invalid_address") from exc

        pins = self._dns_pins()
        if pins is not None:
            previous = pins.get(host)
            if previous is not None and previous != addresses:
                raise ScopeBlockedError(url, "dns_rebinding_toctou")
            pins[host] = addresses
        return addresses

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

        self._enforce_dns_pin(url)

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

    async def _release_host(self, host: str) -> None:
        if self.rate_limiter is not None:
            self.rate_limiter.release(host)

    async def _after_status(self, host: str, status_code: int) -> None:
        if self.rate_limiter is not None:
            try:
                if self.rate_limiter.should_backoff(status_code):
                    await self.rate_limiter.backoff(status_code)
            finally:
                self.rate_limiter.release(host)

    async def _read_limited(
        self,
        response: httpx.Response,
        *,
        url: str,
    ) -> bytes:
        limit = self._response_limit()
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            if not chunk:
                continue
            if limit is not None and total + len(chunk) > limit:
                self.last_metadata["truncated"] = True
                self.last_metadata["response_bytes"] = total + len(chunk)
                raise ResponseTooLargeError(url, limit)
            chunks.append(chunk)
            total += len(chunk)
        self.last_metadata["response_bytes"] = total
        return b"".join(chunks)

    def _materialize(
        self,
        response: httpx.Response,
        content: bytes,
    ) -> httpx.Response:
        request = getattr(response, "request", None)
        if request is None:
            request = httpx.Request("GET", "http://127.0.0.1/")
        return httpx.Response(
            status_code=response.status_code,
            headers=response.headers,
            content=content,
            request=request,
            extensions=dict(getattr(response, "extensions", None) or {}),
            history=list(getattr(response, "history", None) or []),
        )

    async def _send(
        self,
        method: str,
        url: str,
        *,
        mutation: bool,
        **kwargs: Any,
    ) -> httpx.Response:
        client = self._ensure_client()
        current_url = url
        current_method = method.upper()
        current_mutation = mutation
        current_kwargs = dict(kwargs)
        current_kwargs.pop("follow_redirects", None)

        # Production: stream + manual redirects. Unit tests that monkeypatch
        # AsyncClient.get/post/request keep a compatibility path.
        legacy = _client_methods_monkeypatched()
        stream_patched = httpx.AsyncClient.stream is not _ORIGINAL_STREAM

        for hop in range(self.max_redirects + 1):
            for_redirect = hop > 0
            host = await self._before_request(
                current_method,
                current_url,
                mutation=current_mutation,
                for_redirect=for_redirect,
            )
            try:
                if legacy and not stream_patched:
                    clean_kwargs = {
                        key: value
                        for key, value in current_kwargs.items()
                        if value is not None
                    }
                    # Prefer verb-specific monkeypatches when present; otherwise
                    # fall through to request() (also commonly patched in tests).
                    if (
                        current_method == "GET"
                        and httpx.AsyncClient.get is not _ORIGINAL_GET
                    ):
                        response = await client.get(current_url, **clean_kwargs)
                    elif (
                        current_method == "POST"
                        and httpx.AsyncClient.post is not _ORIGINAL_POST
                    ):
                        response = await client.post(current_url, **clean_kwargs)
                    elif (
                        current_method == "HEAD"
                        and httpx.AsyncClient.head is not _ORIGINAL_HEAD
                    ):
                        response = await client.head(current_url, **clean_kwargs)
                    elif (
                        current_method == "OPTIONS"
                        and httpx.AsyncClient.options is not _ORIGINAL_OPTIONS
                    ):
                        response = await client.options(current_url, **clean_kwargs)
                    elif httpx.AsyncClient.request is not _ORIGINAL_REQUEST:
                        response = await client.request(
                            current_method,
                            current_url,
                            **clean_kwargs,
                        )
                    elif current_method == "GET":
                        response = await client.get(current_url, **clean_kwargs)
                    elif current_method == "POST":
                        response = await client.post(current_url, **clean_kwargs)
                    elif current_method == "HEAD":
                        response = await client.head(current_url, **clean_kwargs)
                    elif current_method == "OPTIONS":
                        response = await client.options(current_url, **clean_kwargs)
                    else:
                        response = await client.request(
                            current_method,
                            current_url,
                            **clean_kwargs,
                        )
                    limit = self._response_limit()
                    if limit is not None and len(response.content) > limit:
                        self.last_metadata["truncated"] = True
                        raise ResponseTooLargeError(current_url, limit)
                    if (
                        self.follow_redirects
                        and response.status_code in _REDIRECT_STATUS
                    ):
                        location = response.headers.get("location")
                        await self._after_status(host, response.status_code)
                        if not location:
                            raise ScopeBlockedError(
                                current_url,
                                "redirect_missing_location",
                            )
                        next_url = urljoin(str(response.url), location)
                        if hop >= self.max_redirects:
                            raise TooManyRedirectsError(url, hop + 1)
                        current_url = next_url
                        if response.status_code in {301, 302, 303}:
                            current_method = "GET"
                            current_mutation = False
                            current_kwargs = {}
                        else:
                            current_kwargs = {
                                k: v
                                for k, v in current_kwargs.items()
                                if k not in {"content", "data", "json", "files"}
                            }
                        continue
                    await self._after_status(host, response.status_code)
                    self.last_metadata["response_bytes"] = len(response.content)
                    return response

                async with client.stream(
                    current_method,
                    current_url,
                    **current_kwargs,
                ) as streamed:
                    if (
                        self.follow_redirects
                        and streamed.status_code in _REDIRECT_STATUS
                    ):
                        location = streamed.headers.get("location")
                        try:
                            await self._read_limited(streamed, url=current_url)
                        except ResponseTooLargeError:
                            pass
                        await self._after_status(host, streamed.status_code)
                        if not location:
                            raise ScopeBlockedError(
                                current_url,
                                "redirect_missing_location",
                            )
                        next_url = urljoin(str(streamed.url), location)
                        if hop >= self.max_redirects:
                            raise TooManyRedirectsError(url, hop + 1)
                        current_url = next_url
                        if streamed.status_code in {301, 302, 303}:
                            current_method = "GET"
                            current_mutation = False
                            current_kwargs = {}
                        else:
                            current_kwargs = {
                                k: v
                                for k, v in current_kwargs.items()
                                if k
                                not in {
                                    "content",
                                    "data",
                                    "json",
                                    "files",
                                }
                            }
                        continue

                    content = await self._read_limited(streamed, url=current_url)
                    await self._after_status(host, streamed.status_code)
                    return self._materialize(streamed, content)
            except Exception:
                await self._release_host(host)
                raise

        raise TooManyRedirectsError(url, self.max_redirects)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._send("GET", url, mutation=False, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._send("POST", url, mutation=True, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._send("HEAD", url, mutation=False, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._send("OPTIONS", url, mutation=False, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        mutation = method.upper() not in {"GET", "HEAD", "OPTIONS", "TRACE"}
        return await self._send(method, url, mutation=mutation, **kwargs)

    def stream(self, method: str, url: str, **kwargs: Any):
        client = self._ensure_client()
        kwargs = dict(kwargs)
        kwargs.pop("follow_redirects", None)

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
