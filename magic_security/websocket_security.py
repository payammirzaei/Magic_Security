"""WebSocket Security Pack v1 (STEP 26)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.scope import is_local_target
from magic_security.transport import ScopeBlockedError, assert_url_in_scope


@dataclass
class WebsocketConnectResult:
    url: str
    connected: bool
    origin: str | None = None
    auth_context: str | None = None
    error: str | None = None


@dataclass
class WebsocketPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    connections: list[WebsocketConnectResult] = field(default_factory=list)


async def _try_connect_playwright(
    url: str,
    *,
    origin: str | None = None,
    cookies: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> WebsocketConnectResult:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return WebsocketConnectResult(
            url=url,
            connected=False,
            origin=origin,
            error="playwright_unavailable",
        )

    result = WebsocketConnectResult(url=url, connected=False, origin=origin)
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context_kwargs: dict[str, Any] = {}
            if origin:
                context_kwargs["extra_http_headers"] = {
                    "Origin": origin,
                    **(headers or {}),
                }
            elif headers:
                context_kwargs["extra_http_headers"] = dict(headers)
            browser_context = await browser.new_context(**context_kwargs)
            if cookies:
                parts = urlsplit(url.replace("ws://", "http://").replace(
                    "wss://", "https://"
                ))
                cookie_list = [
                    {
                        "name": name,
                        "value": value,
                        "domain": parts.hostname or "localhost",
                        "path": "/",
                    }
                    for name, value in cookies.items()
                ]
                await browser_context.add_cookies(cookie_list)
            page = await browser_context.new_page()
            connected = await page.evaluate(
                """async ({wsUrl, timeoutMs}) => {
                    return await new Promise((resolve) => {
                        let settled = false;
                        const finish = (value) => {
                            if (settled) return;
                            settled = true;
                            try { socket.close(); } catch (e) {}
                            resolve(value);
                        };
                        let socket;
                        try {
                            socket = new WebSocket(wsUrl);
                        } catch (e) {
                            finish(false);
                            return;
                        }
                        const timer = setTimeout(() => finish(false), timeoutMs);
                        socket.onopen = () => {
                            clearTimeout(timer);
                            finish(true);
                        };
                        socket.onerror = () => {
                            clearTimeout(timer);
                            finish(false);
                        };
                    });
                }""",
                {"wsUrl": url, "timeoutMs": 3000},
            )
            result.connected = bool(connected)
            await browser_context.close()
            await browser.close()
    except Exception as exc:  # noqa: BLE001
        result.error = type(exc).__name__
        result.connected = False
    return result


async def run_websocket_pack(
    crawl: CrawlResult,
    *,
    browser: bool = False,
    auth_contexts: list[AuthContext] | None = None,
    connect_fn=_try_connect_playwright,
) -> WebsocketPackResult:
    result = WebsocketPackResult()
    exercised: list[str] = []
    skipped: list[str] = []
    findings: list[Finding] = []

    ws_urls = sorted(
        url
        for url in crawl.websocket_endpoints
        if url.startswith(("ws://", "wss://"))
    )
    if not ws_urls:
        result.coverage = {
            "pack": "websocket_v1",
            "exercised": [],
            "skipped": ["connect", "origin", "auth_diff", "cswsh", "message_write"],
            "urls": 0,
        }
        return result

    # Plaintext WS on HTTPS page remains Exposure (static observation).
    page_https = any(
        page.url.startswith("https://") for page in crawl.pages
    ) or crawl.target.startswith("https://")
    for url in ws_urls:
        if page_https and url.startswith("ws://"):
            finding = Finding(
                title="Plaintext WebSocket used on HTTPS site",
                severity=Severity.MEDIUM,
                kind=FindingKind.EXPOSURE,
                url=url,
                description=(
                    "A ws:// endpoint was discovered for an HTTPS application."
                ),
                evidence="Discovered websocket URL uses plaintext ws:// scheme.",
                remediation="Use wss:// for WebSocket endpoints on HTTPS sites.",
                confidence=0.95,
                check_id="websocket.plaintext.https",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="websocket.plaintext.https",
                    proof_type="ws_scheme_on_https",
                    baseline_summary="HTTPS pages should use wss://",
                    mutation_summary="Passive scheme inspection",
                    observed_result=finding.evidence,
                    confidence="verified",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    exercised.append("plaintext_scheme")

    if not browser:
        skipped.extend(
            ["connect", "origin", "auth_diff", "cswsh", "message_write"]
        )
        result.findings = findings
        result.coverage = {
            "pack": "websocket_v1",
            "exercised": exercised,
            "skipped": skipped,
            "urls": len(ws_urls),
            "note": "connect probes require --browser",
        }
        return result

    local_urls = [url for url in ws_urls if is_local_target(
        url.replace("ws://", "http://").replace("wss://", "https://")
    )][:5]

    for url in local_urls:
        http_url = url.replace("ws://", "http://").replace("wss://", "https://")
        try:
            assert_url_in_scope(http_url, crawl=crawl)
        except (ScopeBlockedError, RuntimeError):
            continue
        anon = await connect_fn(url, origin=None)
        anon.auth_context = "anonymous"
        result.connections.append(anon)
    exercised.append("connect")

    # Origin posture with controlled foreign origin.
    foreign_origin = "https://magic-security.invalid"
    for url in local_urls:
        http_url = url.replace("ws://", "http://").replace("wss://", "https://")
        try:
            assert_url_in_scope(http_url, crawl=crawl)
        except (ScopeBlockedError, RuntimeError):
            continue
        foreign = await connect_fn(url, origin=foreign_origin)
        foreign.auth_context = "foreign_origin"
        result.connections.append(foreign)
        same_site = urlsplit(
            url.replace("ws://", "http://").replace("wss://", "https://")
        )
        same_origin = f"{same_site.scheme}://{same_site.netloc}"
        local = await connect_fn(url, origin=same_origin)
        local.auth_context = "same_origin"
        result.connections.append(local)

        if foreign.connected:
            finding = Finding(
                title="Cross-origin WebSocket connect accepted",
                severity=Severity.HIGH,
                kind=FindingKind.VULNERABILITY,
                url=url,
                description=(
                    "Server accepted a WebSocket connection from a controlled "
                    "foreign Origin (CSWSH-like posture)."
                ),
                evidence=(
                    f"Origin {foreign_origin} connect accepted=true; "
                    f"same-origin accepted={local.connected}."
                ),
                remediation=(
                    "Validate Origin (and auth cookies) before upgrading "
                    "WebSocket connections."
                ),
                confidence=1.0,
                check_id="websocket.cswsh.accepted",
                cwe="CWE-346",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="websocket.cswsh.accepted",
                    proof_type="cross_origin_ws_accepted",
                    baseline_summary="Foreign origin should be rejected",
                    mutation_summary=f"Connected with Origin {foreign_origin}",
                    observed_result=finding.evidence,
                    confidence="verified",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
        else:
            finding = Finding(
                title="Cross-origin WebSocket connect rejected",
                severity=Severity.INFO,
                kind=FindingKind.HARDENING,
                url=url,
                description="Foreign Origin WebSocket connect was not accepted.",
                evidence=(
                    f"Origin {foreign_origin} connect accepted=false."
                ),
                remediation="Keep rejecting untrusted WebSocket origins.",
                confidence=0.85,
                check_id="websocket.origin.rejected",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="websocket.origin.rejected",
                    proof_type="cross_origin_ws_rejected",
                    baseline_summary="Foreign origin connect attempt",
                    mutation_summary=f"Origin {foreign_origin}",
                    observed_result=finding.evidence,
                    confidence="likely",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    exercised.append("origin")
    exercised.append("cswsh")

    if auth_contexts:
        for context in auth_contexts[:2]:
            for url in local_urls[:2]:
                auth_conn = await connect_fn(
                    url,
                    cookies=context.cookies,
                    headers=context.headers,
                )
                auth_conn.auth_context = context.name
                result.connections.append(auth_conn)
        exercised.append("auth_diff")
        anon_ok = {
            item.url
            for item in result.connections
            if item.auth_context == "anonymous" and item.connected
        }
        auth_ok = {
            item.url
            for item in result.connections
            if item.auth_context not in {None, "anonymous", "foreign_origin", "same_origin"}
            and item.connected
        }
        for url in sorted(auth_ok - anon_ok):
            finding = Finding(
                title="WebSocket requires authentication to connect",
                severity=Severity.INFO,
                kind=FindingKind.HARDENING,
                url=url,
                description=(
                    "Authenticated contexts could connect while anonymous "
                    "could not."
                ),
                evidence="Anonymous connect failed; auth connect succeeded.",
                remediation="Keep requiring auth for sensitive WS channels.",
                confidence=0.85,
                check_id="websocket.auth.required",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="websocket.auth.required",
                    proof_type="ws_auth_differential",
                    baseline_summary="Anonymous connect attempt",
                    mutation_summary="Authenticated connect attempt",
                    observed_result=finding.evidence,
                    confidence="likely",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    else:
        skipped.append("auth_diff")

    skipped.append("message_write")  # requires workflow
    result.findings = findings
    result.coverage = {
        "pack": "websocket_v1",
        "exercised": exercised,
        "skipped": skipped,
        "urls": len(ws_urls),
        "connections": len(result.connections),
        "message_write": "requires_workflow",
    }
    return result
