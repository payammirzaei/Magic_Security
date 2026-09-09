from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from magic_security.transport import SecureTransport
from bs4 import BeautifulSoup

from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import (
    Finding,
    FindingKind,
    InjectionObservation,
    NormalizedEndpoint,
    Severity,
)
from magic_security.scope import is_loopback_url as _is_loopback_url


def _set_query(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    items = [
        (key, current)
        for key, current in parse_qsl(
            parts.query,
            keep_blank_values=True,
        )
        if key != parameter
    ]
    items.append((parameter, value))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(items),
            parts.fragment,
        )
    )


async def verify_reflected_html_injection(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_tests: int = 30,
) -> tuple[list[InjectionObservation], list[Finding]]:
    observations: list[InjectionObservation] = []
    findings: list[Finding] = []
    tested = 0

    async with SecureTransport(
        follow_redirects=False,
        timeout=timeout,
    ) as client:
        for endpoint in endpoints:
            if tested >= max_tests:
                break
            if endpoint.method.upper() != "GET":
                continue
            if "{" in endpoint.url or "}" in endpoint.url:
                continue

            for parameter in endpoint.parameters:
                if tested >= max_tests:
                    break

                tested += 1
                token = "ms-" + secrets.token_hex(6)
                payload = (
                    f'<ms-security-probe data-token="{token}">'
                    "</ms-security-probe>"
                )
                probe_url = _set_query(
                    endpoint.url,
                    parameter,
                    payload,
                )

                try:
                    response = await client.get(
                        probe_url,
                        headers={
                            "User-Agent": (
                                "Magic-Security/0.7 "
                                "local-security-scanner"
                            )
                        },
                    )
                except httpx.HTTPError:
                    continue

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                if (
                    response.status_code != 200
                    or "html" not in content_type
                ):
                    continue

                raw_reflected = token in response.text
                html_inserted = False

                if raw_reflected:
                    soup = BeautifulSoup(
                        response.text,
                        "html.parser",
                    )
                    html_inserted = any(
                        node.get("data-token") == token
                        for node in soup.find_all(
                            "ms-security-probe"
                        )
                    )

                observations.append(
                    InjectionObservation(
                        url=endpoint.url,
                        parameter=parameter,
                        raw_reflected=raw_reflected,
                        html_injection_verified=html_inserted,
                        script_execution_verified=False,
                    )
                )

                if not html_inserted:
                    continue

                finding = Finding(
                    title="Reflected HTML injection verified",
                    severity=Severity.MEDIUM,
                    kind=FindingKind.VULNERABILITY,
                    url=endpoint.url,
                    description=(
                        "A controlled query value was inserted "
                        "into returned HTML as markup instead of "
                        "being safely encoded."
                    ),
                    evidence=(
                        f"Parameter {parameter!r} created the "
                        "scanner's inert custom HTML element in "
                        "the parsed response. The random canary "
                        "value was not retained."
                    ),
                    remediation=(
                        "Apply context-aware output encoding and "
                        "avoid inserting untrusted values with raw "
                        "HTML rendering APIs."
                    ),
                    confidence=1.0,
                    cwe="CWE-79",
                    check_id="injection.html.reflected",
                )
                attach_evidence(
                    finding,
                    EvidenceObject(
                        check_id="injection.html.reflected",
                        proof_type="raw_html_reflection",
                        baseline_summary="Parameter value safely encoded in HTML",
                        mutation_summary=(
                            f"Injected inert markup via parameter {parameter!r}"
                        ),
                        observed_result=finding.evidence,
                        confidence="verified",
                        sensitive_values_stored=False,
                    ),
                )
                findings.append(finding)

    return observations, findings


async def verify_reflected_xss_browser(
    endpoints: list[NormalizedEndpoint],
    *,
    max_tests: int = 15,
) -> tuple[list[InjectionObservation], list[Finding]]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return [], []

    observations: list[InjectionObservation] = []
    findings: list[Finding] = []
    tested = 0

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(
                headless=True
            )
        except Exception:
            return [], []

        context = await browser.new_context(
            ignore_https_errors=True,
            service_workers="block",
        )

        async def route_handler(route):
            if _is_loopback_url(route.request.url):
                await route.continue_()
            else:
                await route.abort()

        await context.route("**/*", route_handler)

        page = await context.new_page()
        page.set_default_navigation_timeout(6_000)

        for endpoint in endpoints:
            if tested >= max_tests:
                break
            if endpoint.method.upper() != "GET":
                continue
            if "{" in endpoint.url or "}" in endpoint.url:
                continue

            for parameter in endpoint.parameters:
                if tested >= max_tests:
                    break

                tested += 1
                token = "msxss-" + secrets.token_hex(6)
                payload = (
                    '<svg onload="document.documentElement.'
                    f"setAttribute('data-ms-xss','{token}')"
                    '"></svg>'
                )
                probe_url = _set_query(
                    endpoint.url,
                    parameter,
                    payload,
                )

                try:
                    await page.goto(
                        probe_url,
                        wait_until="domcontentloaded",
                    )
                    await page.wait_for_timeout(150)
                    executed = await page.evaluate(
                        """(token) =>
                        document.documentElement.getAttribute(
                            'data-ms-xss'
                        ) === token""",
                        token,
                    )
                except Exception:
                    continue

                if not executed:
                    continue

                observations.append(
                    InjectionObservation(
                        url=endpoint.url,
                        parameter=parameter,
                        raw_reflected=True,
                        html_injection_verified=True,
                        script_execution_verified=True,
                    )
                )

                findings.append(
                    Finding(
                        title="Reflected XSS execution verified",
                        severity=Severity.HIGH,
                        kind=FindingKind.VULNERABILITY,
                        url=endpoint.url,
                        description=(
                            "A controlled reflected value executed "
                            "JavaScript in the target browser origin."
                        ),
                        evidence=(
                            f"Parameter {parameter!r} executed a "
                            "non-network DOM-only canary in a "
                            "headless browser. No cookies, storage "
                            "values, or external callbacks were read."
                        ),
                        remediation=(
                            "Use context-aware output encoding, remove "
                            "unsafe raw HTML rendering, and deploy a "
                            "restrictive CSP as defense in depth."
                        ),
                        confidence=1.0,
                        cwe="CWE-79",
                    )
                )

        await context.close()
        await browser.close()

    return observations, findings
