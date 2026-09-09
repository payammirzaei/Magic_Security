from __future__ import annotations

import json
import re
from collections.abc import Iterable
from urllib.parse import quote, urlsplit

import httpx

from magic_security.transport import open_secure_transport
from magic_security.scope import is_loopback_url as _is_loopback_url

from magic_security.models import (
    AuthContext,
    BrowserSecurityCoverage,
    BrowserSecurityObservation,
    Finding,
    FindingKind,
    Severity,
)


_DOM_SOURCES = {
    "location.search": re.compile(r"\blocation\.search\b", re.I),
    "location.hash": re.compile(r"\blocation\.hash\b", re.I),
    "document.URL": re.compile(r"\bdocument\.URL\b", re.I),
    "document.referrer": re.compile(r"\bdocument\.referrer\b", re.I),
    "window.name": re.compile(r"\bwindow\.name\b", re.I),
}
_DOM_SINKS = {
    "innerHTML": re.compile(r"\.innerHTML\s*=", re.I),
    "outerHTML": re.compile(r"\.outerHTML\s*=", re.I),
    "insertAdjacentHTML": re.compile(r"\binsertAdjacentHTML\s*\(", re.I),
    "document.write": re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.I),
    "eval": re.compile(r"\beval\s*\(", re.I),
    "Function": re.compile(r"\bnew\s+Function\s*\(", re.I),
}
_REDIRECT_SINKS = {
    "location.href": re.compile(r"\blocation\.href\s*=", re.I),
    "location.assign": re.compile(r"\blocation\.assign\s*\(", re.I),
    "location.replace": re.compile(r"\blocation\.replace\s*\(", re.I),
}
_MESSAGE_LISTENER = re.compile(
    r"""(?:addEventListener\s*\(\s*["']message["']|onmessage\s*=)""",
    re.I,
)
_ORIGIN_CHECK = re.compile(
    r"""(?:\bevent\.origin\b|\bmessage\.origin\b|allowedOrigins|trustedOrigins)""",
    re.I,
)
_WEBSOCKET = re.compile(
    r"""\bnew\s+WebSocket\s*\(\s*["'](?P<url>wss?://[^"']+)["']""",
    re.I,
)
_SENSITIVE_STORAGE_TOKENS = (
    "token",
    "jwt",
    "auth",
    "session",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
)


def storage_observations_from_keys(
    *,
    page_url: str,
    context_name: str,
    local_keys: list[str],
    session_keys: list[str],
) -> list[BrowserSecurityObservation]:
    observations: list[BrowserSecurityObservation] = []

    for storage_type, keys in (
        ("localStorage", local_keys),
        ("sessionStorage", session_keys),
    ):
        for key in keys:
            lowered = key.lower()
            if not any(
                token in lowered
                for token in _SENSITIVE_STORAGE_TOKENS
            ):
                continue
            observations.append(
                BrowserSecurityObservation(
                    category="browser_storage",
                    url=page_url,
                    status="sensitive_key_observed",
                    context=context_name,
                    evidence=(
                        f"{storage_type} contains security-relevant key "
                        f"{key!r}. The stored value was not read or recorded."
                    ),
                )
            )

    return observations


def _analyze_text(
    url: str,
    text: str,
    artifact_type: str,
) -> tuple[list[BrowserSecurityObservation], set[str]]:
    observations: list[BrowserSecurityObservation] = []
    websockets = {
        match.group("url")
        for match in _WEBSOCKET.finditer(text)
    }

    sources = tuple(
        name
        for name, pattern in _DOM_SOURCES.items()
        if pattern.search(text)
    )
    sinks = tuple(
        name
        for name, pattern in _DOM_SINKS.items()
        if pattern.search(text)
    )
    redirects = tuple(
        name
        for name, pattern in _REDIRECT_SINKS.items()
        if pattern.search(text)
    )

    if sources and sinks:
        observations.append(
            BrowserSecurityObservation(
                category="dom_xss",
                url=url,
                status="source_sink_candidate",
                evidence=(
                    f"{artifact_type} contains browser-controlled source(s) "
                    f"{', '.join(sources)} and unsafe DOM sink(s) "
                    f"{', '.join(sinks)}."
                ),
            )
        )

    if sources and redirects:
        observations.append(
            BrowserSecurityObservation(
                category="client_redirect",
                url=url,
                status="source_sink_candidate",
                evidence=(
                    f"{artifact_type} combines URL source(s) "
                    f"{', '.join(sources)} with navigation sink(s) "
                    f"{', '.join(redirects)}."
                ),
            )
        )

    if _MESSAGE_LISTENER.search(text):
        origin_checked = bool(_ORIGIN_CHECK.search(text))
        observations.append(
            BrowserSecurityObservation(
                category="web_messaging",
                url=url,
                status=(
                    "origin_check_signal"
                    if origin_checked
                    else "missing_origin_check_signal"
                ),
                evidence=(
                    "A message event handler was found; "
                    + (
                        "an origin-validation signal is present."
                        if origin_checked
                        else "no obvious event.origin validation signal was found."
                    )
                ),
            )
        )

    for websocket in sorted(websockets):
        observations.append(
            BrowserSecurityObservation(
                category="websocket",
                url=websocket,
                status="discovered",
                evidence=(
                    f"WebSocket endpoint referenced by {artifact_type}."
                ),
            )
        )

        if url.startswith("https://") and websocket.startswith("ws://"):
            observations.append(
                BrowserSecurityObservation(
                    category="websocket",
                    url=websocket,
                    status="insecure_transport",
                    evidence=(
                        "An HTTPS-delivered client artifact references a "
                        "plaintext ws:// WebSocket endpoint."
                    ),
                )
            )

    return observations, websockets


async def analyze_browser_artifacts(
    js_assets: Iterable[str],
    source_maps: Iterable[str],
    *,
    timeout: float = 5.0,
    max_assets: int = 40,
) -> tuple[
    list[BrowserSecurityObservation],
    set[str],
    list[Finding],
]:
    observations: list[BrowserSecurityObservation] = []
    websockets: set[str] = set()
    findings: list[Finding] = []

    assets = [
        (url, "frontend JavaScript")
        for url in sorted(set(js_assets))
    ]
    assets.extend(
        (url, "source map")
        for url in sorted(set(source_maps))
    )

    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
    ) as client:
        for url, artifact_type in assets[:max_assets]:
            try:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": (
                            "Magic-Security/0.8 local-security-scanner"
                        )
                    },
                )
            except httpx.HTTPError:
                continue
            if response.status_code != 200:
                continue

            texts: list[tuple[str, str]] = [
                (artifact_type, response.text[:1_000_000])
            ]

            if artifact_type == "source map":
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    data = None
                if (
                    isinstance(data, dict)
                    and isinstance(data.get("sourcesContent"), list)
                ):
                    texts = [
                        (
                            "source-map embedded source",
                            item[:1_000_000],
                        )
                        for item in data["sourcesContent"][:100]
                        if isinstance(item, str)
                    ]

            for label, text in texts:
                obs, sockets = _analyze_text(url, text, label)
                observations.extend(obs)
                websockets.update(sockets)

    for item in observations:
        if (
            item.category == "web_messaging"
            and item.status == "missing_origin_check_signal"
        ):
            findings.append(
                Finding(
                    title="Web message handler lacks an obvious origin check",
                    severity=Severity.LOW,
                    kind=FindingKind.EXPOSURE,
                    url=item.url,
                    description=(
                        "Frontend code registers a cross-window message handler "
                        "without an obvious origin-validation signal."
                    ),
                    evidence=item.evidence,
                    remediation=(
                        "Validate event.origin against a strict trusted-origin "
                        "allowlist before processing message data."
                    ),
                    confidence=0.7,
                    cwe="CWE-346",
                )
            )

        elif (
            item.category == "client_redirect"
            and item.status == "source_sink_candidate"
        ):
            findings.append(
                Finding(
                    title="Potential client-side redirect flow",
                    severity=Severity.LOW,
                    kind=FindingKind.EXPOSURE,
                    url=item.url,
                    description=(
                        "Client code combines browser-controlled URL input with "
                        "client-side navigation sinks."
                    ),
                    evidence=item.evidence,
                    remediation=(
                        "Restrict client-side redirect destinations to safe "
                        "relative paths or an explicit allowlist."
                    ),
                    confidence=0.6,
                    cwe="CWE-601",
                )
            )

        elif (
            item.category == "dom_xss"
            and item.status == "source_sink_candidate"
        ):
            findings.append(
                Finding(
                    title="Potential DOM XSS source-to-sink path",
                    severity=Severity.LOW,
                    kind=FindingKind.EXPOSURE,
                    url=item.url,
                    description=(
                        "Browser-controlled input sources and unsafe DOM sinks "
                        "coexist in a client artifact."
                    ),
                    evidence=item.evidence,
                    remediation=(
                        "Trace the data flow and replace unsafe sinks or apply "
                        "context-appropriate sanitization."
                    ),
                    confidence=0.65,
                    cwe="CWE-79",
                )
            )

        elif (
            item.category == "websocket"
            and item.status == "insecure_transport"
        ):
            findings.append(
                Finding(
                    title="Secure page references plaintext WebSocket transport",
                    severity=Severity.MEDIUM,
                    kind=FindingKind.EXPOSURE,
                    url=item.url,
                    description=(
                        "An HTTPS-delivered frontend references ws:// instead of "
                        "wss:// for WebSocket communication."
                    ),
                    evidence=item.evidence,
                    remediation=(
                        "Use wss:// for WebSocket traffic on secure applications."
                    ),
                    confidence=1.0,
                    cwe="CWE-319",
                )
            )

    return observations, websockets, findings


def storage_findings(
    observations: list[BrowserSecurityObservation],
) -> list[Finding]:
    findings: list[Finding] = []
    for item in observations:
        if (
            item.category != "browser_storage"
            or item.status != "sensitive_key_observed"
        ):
            continue
        findings.append(
            Finding(
                title="Sensitive-looking browser storage key observed",
                severity=Severity.LOW,
                kind=FindingKind.EXPOSURE,
                url=item.url,
                description=(
                    "A JavaScript-accessible browser storage entry has a "
                    "security-relevant key name."
                ),
                evidence=item.evidence,
                remediation=(
                    "Avoid keeping bearer credentials or sensitive session "
                    "material in localStorage/sessionStorage when a safer "
                    "server-side or HttpOnly-cookie design is available."
                ),
                confidence=0.9,
                cwe="CWE-922",
            )
        )
    return findings


async def verify_dom_xss_browser(
    page_urls: list[str],
    *,
    auth_contexts: list[AuthContext] | None = None,
    max_pages: int = 20,
) -> tuple[list[BrowserSecurityObservation], list[Finding]]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return [], []

    observations: list[BrowserSecurityObservation] = []
    findings: list[Finding] = []
    token = "magic-dom-xss"
    payload = (
        "<svg onload=\"document.documentElement."
        "setAttribute('data-ms-dom-xss','magic-dom-xss')\"></svg>"
    )
    fragment = quote(payload, safe="")

    contexts: list[AuthContext | None] = [None]
    contexts.extend(auth_contexts or [])

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(headless=True)
        except Exception:
            return [], []

        for auth_context in contexts:
            label = auth_context.name if auth_context else "anonymous"
            kwargs: dict = {
                "ignore_https_errors": True,
                "service_workers": "block",
            }
            if auth_context and auth_context.headers:
                kwargs["extra_http_headers"] = auth_context.headers

            context = await browser.new_context(**kwargs)

            if auth_context and auth_context.cookies and page_urls:
                base = urlsplit(page_urls[0])
                origin = f"{base.scheme}://{base.netloc}"
                await context.add_cookies(
                    [
                        {
                            "name": key,
                            "value": value,
                            "url": origin,
                        }
                        for key, value in auth_context.cookies.items()
                    ]
                )

            async def route_handler(route):
                if _is_loopback_url(route.request.url):
                    await route.continue_()
                else:
                    await route.abort()

            await context.route("**/*", route_handler)
            page = await context.new_page()
            page.set_default_navigation_timeout(6_000)

            for url in list(dict.fromkeys(page_urls))[:max_pages]:
                target = url.split("#", 1)[0] + "#" + fragment

                try:
                    await page.goto(
                        target,
                        wait_until="domcontentloaded",
                    )
                    await page.wait_for_timeout(200)
                    executed = await page.evaluate(
                        """(token) =>
                        document.documentElement.getAttribute(
                            'data-ms-dom-xss'
                        ) === token""",
                        token,
                    )
                except Exception:
                    continue

                if not executed:
                    continue

                observations.append(
                    BrowserSecurityObservation(
                        category="dom_xss",
                        url=url,
                        status="execution_verified",
                        context=label,
                        evidence=(
                            "A DOM-only fragment canary executed in the page. "
                            "No storage, cookies, or network callback was read."
                        ),
                    )
                )
                findings.append(
                    Finding(
                        title="DOM-based XSS execution verified",
                        severity=Severity.HIGH,
                        kind=FindingKind.VULNERABILITY,
                        url=url,
                        description=(
                            "Browser-controlled fragment data reached an executable "
                            "DOM sink in the target origin."
                        ),
                        evidence=(
                            f"A harmless DOM-only canary executed in context "
                            f"{label!r}. No application data was accessed."
                        ),
                        remediation=(
                            "Avoid inserting untrusted data into executable HTML "
                            "sinks; use safe DOM APIs and contextual sanitization."
                        ),
                        confidence=1.0,
                        cwe="CWE-79",
                    )
                )

            await context.close()

        await browser.close()

    return observations, findings


def build_browser_security_coverage(
    observations: list[BrowserSecurityObservation],
    websockets: set[str],
    *,
    artifacts_scanned: int,
) -> BrowserSecurityCoverage:
    return BrowserSecurityCoverage(
        artifacts_scanned=artifacts_scanned,
        dom_source_sink_candidates=sum(
            1
            for item in observations
            if item.category == "dom_xss"
            and item.status == "source_sink_candidate"
        ),
        dom_xss_verified=sum(
            1
            for item in observations
            if item.category == "dom_xss"
            and item.status == "execution_verified"
        ),
        message_handlers=sum(
            1
            for item in observations
            if item.category == "web_messaging"
        ),
        message_handlers_missing_origin=sum(
            1
            for item in observations
            if item.category == "web_messaging"
            and item.status == "missing_origin_check_signal"
        ),
        client_redirect_candidates=sum(
            1
            for item in observations
            if item.category == "client_redirect"
        ),
        sensitive_storage_keys=sum(
            1
            for item in observations
            if item.category == "browser_storage"
            and item.status == "sensitive_key_observed"
        ),
        websocket_endpoints=len(websockets),
    )
