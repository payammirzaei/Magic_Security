from __future__ import annotations

import asyncio
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from magic_security.transport import open_secure_transport

from magic_security.models import (
    Finding,
    FindingKind,
    NormalizedEndpoint,
    ServerProbeObservation,
    Severity,
)
from magic_security.scope import is_loopback_url as _is_loopback_url


_FILE_PARAMETERS = {
    "file",
    "filename",
    "path",
    "filepath",
    "template",
    "page",
    "document",
    "doc",
    "download",
    "folder",
}
_SSRF_PARAMETERS = {
    "url",
    "uri",
    "endpoint",
    "callback",
    "callback_url",
    "webhook",
    "webhook_url",
    "image",
    "image_url",
    "src",
    "source",
    "fetch",
    "proxy",
    "target",
}
_AUTH_PATH_MARKERS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/auth/token",
    "/oauth/token",
    "/token",
)


def _set_query(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [
        (key, current)
        for key, current in parse_qsl(
            parts.query,
            keep_blank_values=True,
        )
        if key != parameter
    ]
    pairs.append((parameter, value))
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(pairs, doseq=True),
            parts.fragment,
        )
    )


def _concrete_get_candidates(
    endpoints: list[NormalizedEndpoint],
) -> list[NormalizedEndpoint]:
    return [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "GET"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
        and _is_loopback_url(endpoint.url)
    ]


async def verify_path_traversal(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_tests: int = 20,
) -> tuple[list[ServerProbeObservation], list[Finding]]:
    observations: list[ServerProbeObservation] = []
    findings: list[Finding] = []
    tested = 0

    probes = (
        (
            "../../../../etc/hosts",
            ("127.0.0.1", "localhost"),
            "unix_hosts",
        ),
        (
            "..\\..\\..\\Windows\\win.ini",
            ("[fonts]", "[extensions]"),
            "windows_win_ini",
        ),
    )

    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.9 server-security",
        },
    ) as client:
        for endpoint in _concrete_get_candidates(endpoints):
            parameters = [
                item
                for item in endpoint.parameters
                if item.lower() in _FILE_PARAMETERS
            ]

            for parameter in parameters:
                baseline_url = _set_query(
                    endpoint.url,
                    parameter,
                    "magic-security-file-does-not-exist",
                )
                try:
                    baseline = await client.get(baseline_url)
                except httpx.HTTPError:
                    continue

                baseline_text = baseline.text[:200_000].lower()

                for payload, markers, label in probes:
                    if tested >= max_tests:
                        return observations, findings
                    tested += 1

                    try:
                        response = await client.get(
                            _set_query(
                                endpoint.url,
                                parameter,
                                payload,
                            )
                        )
                    except httpx.HTTPError:
                        continue

                    body = response.text[:200_000].lower()
                    verified = all(
                        marker.lower() in body
                        and marker.lower() not in baseline_text
                        for marker in markers
                    )

                    observations.append(
                        ServerProbeObservation(
                            category="path_traversal",
                            url=endpoint.url,
                            parameter=parameter,
                            status_code=response.status_code,
                            verified=verified,
                            detail=label if verified else "marker_not_observed",
                        )
                    )

                    if verified:
                        findings.append(
                            Finding(
                                title="Path traversal / local file read verified",
                                severity=Severity.HIGH,
                                kind=FindingKind.VULNERABILITY,
                                url=endpoint.url,
                                description=(
                                    f"Parameter {parameter!r} allowed a traversal "
                                    "sequence to read a known operating-system "
                                    "marker file."
                                ),
                                evidence=(
                                    f"The response matched the non-secret marker "
                                    f"set {label!r}. File contents were not stored."
                                ),
                                remediation=(
                                    "Resolve files from a fixed allowlisted root, "
                                    "reject traversal segments, and avoid accepting "
                                    "raw filesystem paths."
                                ),
                                confidence=1.0,
                                cwe="CWE-22",
                            )
                        )
                        break

    return observations, findings


class _CallbackHandler(BaseHTTPRequestHandler):
    hits: set[str] = set()
    lock = threading.Lock()

    def do_GET(self) -> None:
        token = self.path.lstrip("/").split("?", 1)[0]
        with self.lock:
            self.hits.add(token)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


async def verify_ssrf_callback(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_tests: int = 15,
) -> tuple[list[ServerProbeObservation], list[Finding]]:
    observations: list[ServerProbeObservation] = []
    findings: list[Finding] = []
    tested = 0

    callback_server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        _CallbackHandler,
    )
    _CallbackHandler.hits = set()
    thread = threading.Thread(
        target=callback_server.serve_forever,
        daemon=True,
    )
    thread.start()
    port = int(callback_server.server_address[1])

    try:
        async with open_secure_transport(
            follow_redirects=False,
            timeout=timeout,
            headers={
                "User-Agent": "Magic-Security/0.9 server-security",
            },
        ) as client:
            for endpoint in _concrete_get_candidates(endpoints):
                parameters = [
                    item
                    for item in endpoint.parameters
                    if item.lower() in _SSRF_PARAMETERS
                ]

                for parameter in parameters:
                    if tested >= max_tests:
                        return observations, findings
                    tested += 1

                    token = secrets.token_hex(12)
                    callback = f"http://127.0.0.1:{port}/{token}"

                    try:
                        response = await client.get(
                            _set_query(
                                endpoint.url,
                                parameter,
                                callback,
                            )
                        )
                    except httpx.HTTPError:
                        continue

                    await asyncio.sleep(0.1)
                    with _CallbackHandler.lock:
                        verified = token in _CallbackHandler.hits

                    observations.append(
                        ServerProbeObservation(
                            category="ssrf",
                            url=endpoint.url,
                            parameter=parameter,
                            status_code=response.status_code,
                            verified=verified,
                            detail=(
                                "local_callback_received"
                                if verified
                                else "no_callback_received"
                            ),
                        )
                    )

                    if verified:
                        findings.append(
                            Finding(
                                title="Server-side request forgery verified",
                                severity=Severity.HIGH,
                                kind=FindingKind.VULNERABILITY,
                                url=endpoint.url,
                                description=(
                                    f"Parameter {parameter!r} caused the target "
                                    "server to request a scanner-owned loopback "
                                    "callback."
                                ),
                                evidence=(
                                    "A unique callback token was received by the "
                                    "local scanner callback server. No external "
                                    "host or metadata endpoint was contacted."
                                ),
                                remediation=(
                                    "Allowlist outbound destinations and block "
                                    "loopback/private/link-local targets after DNS "
                                    "resolution and redirect handling."
                                ),
                                confidence=1.0,
                                cwe="CWE-918",
                            )
                        )

    finally:
        callback_server.shutdown()
        callback_server.server_close()
        thread.join(timeout=1.0)

    return observations, findings


def _auth_success_signal(response: httpx.Response) -> bool:
    if not (200 <= response.status_code < 300):
        return False

    if any(
        re.search(
            r"(session|auth|token|jwt|sid)",
            cookie,
            re.I,
        )
        for cookie in response.headers.get_list("set-cookie")
    ):
        return True

    try:
        data = response.json()
    except ValueError:
        return False

    if not isinstance(data, dict):
        return False

    return bool(
        {str(key).lower() for key in data}
        & {
            "token",
            "access_token",
            "refresh_token",
            "jwt",
            "session",
            "user",
        }
    )


def _auth_candidates(
    endpoints: list[NormalizedEndpoint],
) -> list[NormalizedEndpoint]:
    return [
        endpoint
        for endpoint in endpoints
        if endpoint.method.upper() == "POST"
        and "{" not in endpoint.url
        and "}" not in endpoint.url
        and _is_loopback_url(endpoint.url)
        and any(
            marker in endpoint.url.lower()
            for marker in _AUTH_PATH_MARKERS
        )
    ]


async def verify_auth_injection_bypass(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_endpoints: int = 8,
) -> tuple[list[ServerProbeObservation], list[Finding]]:
    observations: list[ServerProbeObservation] = []
    findings: list[Finding] = []

    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.9 server-security",
        },
    ) as client:
        for endpoint in _auth_candidates(endpoints)[:max_endpoints]:
            baseline_payload = {
                "email": "magic-security-invalid@example.invalid",
                "username": "magic-security-invalid",
                "password": "invalid-magic-security-password",
            }

            try:
                baseline = await client.post(
                    endpoint.url,
                    json=baseline_payload,
                )
            except httpx.HTTPError:
                continue

            baseline_success = _auth_success_signal(baseline)

            sql_payload = {
                "email": "ms' OR '1'='1' -- ",
                "username": "ms' OR '1'='1' -- ",
                "password": "invalid-magic-security-password",
            }

            try:
                sql_response = await client.post(
                    endpoint.url,
                    json=sql_payload,
                )
            except httpx.HTTPError:
                sql_response = None

            sql_verified = bool(
                sql_response is not None
                and not baseline_success
                and _auth_success_signal(sql_response)
            )

            observations.append(
                ServerProbeObservation(
                    category="auth_sqli",
                    url=endpoint.url,
                    parameter="credentials",
                    status_code=(
                        sql_response.status_code
                        if sql_response is not None
                        else 0
                    ),
                    verified=sql_verified,
                    detail=(
                        "authentication_bypass"
                        if sql_verified
                        else "not_verified"
                    ),
                )
            )

            if sql_verified:
                findings.append(
                    Finding(
                        title="SQL-style authentication bypass verified",
                        severity=Severity.CRITICAL,
                        kind=FindingKind.VULNERABILITY,
                        url=endpoint.url,
                        description=(
                            "Synthetic SQL-style credentials changed an "
                            "invalid-login baseline into an authenticated "
                            "success signal."
                        ),
                        evidence=(
                            "The baseline invalid login was not successful; "
                            "the SQL-style probe returned 2xx plus a session/"
                            "token signal. No real credentials were used."
                        ),
                        remediation=(
                            "Use parameterized credential lookups and enforce "
                            "strict scalar input schemas."
                        ),
                        confidence=1.0,
                        cwe="CWE-89",
                    )
                )

            nosql_payload = {
                "email": {"$ne": None},
                "username": {"$ne": None},
                "password": {"$ne": None},
            }

            try:
                nosql_response = await client.post(
                    endpoint.url,
                    json=nosql_payload,
                )
            except httpx.HTTPError:
                nosql_response = None

            nosql_verified = bool(
                nosql_response is not None
                and not baseline_success
                and _auth_success_signal(nosql_response)
            )

            observations.append(
                ServerProbeObservation(
                    category="auth_nosqli",
                    url=endpoint.url,
                    parameter="credentials",
                    status_code=(
                        nosql_response.status_code
                        if nosql_response is not None
                        else 0
                    ),
                    verified=nosql_verified,
                    detail=(
                        "authentication_bypass"
                        if nosql_verified
                        else "not_verified"
                    ),
                )
            )

            if nosql_verified:
                findings.append(
                    Finding(
                        title="NoSQL operator authentication bypass verified",
                        severity=Severity.CRITICAL,
                        kind=FindingKind.VULNERABILITY,
                        url=endpoint.url,
                        description=(
                            "Synthetic NoSQL operator objects changed an "
                            "invalid-login baseline into an authenticated "
                            "success signal."
                        ),
                        evidence=(
                            "The baseline invalid login was not successful; "
                            "the $ne probe returned 2xx plus a session/token "
                            "signal. No real credentials were used."
                        ),
                        remediation=(
                            "Enforce scalar credential schemas and never pass "
                            "untrusted query objects/operators into database "
                            "credential lookups."
                        ),
                        confidence=1.0,
                        cwe="CWE-943",
                    )
                )

    return observations, findings


async def verify_host_header_poisoning(
    urls: list[str],
    *,
    timeout: float = 5.0,
    max_tests: int = 10,
) -> tuple[list[ServerProbeObservation], list[Finding]]:
    observations: list[ServerProbeObservation] = []
    findings: list[Finding] = []
    marker = "magic-security.invalid"

    async with open_secure_transport(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/0.9 server-security",
        },
    ) as client:
        for url in list(dict.fromkeys(urls))[:max_tests]:
            if not _is_loopback_url(url):
                continue

            try:
                baseline = await client.get(url)
                probe = await client.get(
                    url,
                    headers={
                        "Host": marker,
                        "X-Forwarded-Host": marker,
                    },
                )
            except httpx.HTTPError:
                continue

            baseline_text = (
                baseline.headers.get("location", "")
                + "\n"
                + baseline.text[:100_000]
            ).lower()
            probe_text = (
                probe.headers.get("location", "")
                + "\n"
                + probe.text[:100_000]
            ).lower()

            verified = (
                marker in probe_text
                and marker not in baseline_text
            )

            observations.append(
                ServerProbeObservation(
                    category="host_header",
                    url=url,
                    parameter="Host/X-Forwarded-Host",
                    status_code=probe.status_code,
                    verified=verified,
                    detail=(
                        "attacker_host_influenced_response"
                        if verified
                        else "not_observed"
                    ),
                )
            )

            if verified:
                findings.append(
                    Finding(
                        title="Untrusted Host header influences response content",
                        severity=Severity.MEDIUM,
                        kind=FindingKind.EXPOSURE,
                        url=url,
                        description=(
                            "A scanner-controlled Host/X-Forwarded-Host value "
                            "was incorporated into response content or Location."
                        ),
                        evidence=(
                            "The marker host appeared only in the poisoned-host "
                            "response. No password-reset poisoning was claimed."
                        ),
                        remediation=(
                            "Validate Host against an explicit allowlist and "
                            "configure trusted proxy host handling correctly."
                        ),
                        confidence=1.0,
                        cwe="CWE-346",
                    )
                )

    return observations, findings


async def run_server_security_pack(
    endpoints: list[NormalizedEndpoint],
    page_urls: list[str],
) -> tuple[list[ServerProbeObservation], list[Finding]]:
    observations: list[ServerProbeObservation] = []
    findings: list[Finding] = []

    for check in (
        verify_path_traversal,
        verify_ssrf_callback,
        verify_auth_injection_bypass,
    ):
        check_observations, check_findings = await check(endpoints)
        observations.extend(check_observations)
        findings.extend(check_findings)

    host_observations, host_findings = await verify_host_header_poisoning(
        page_urls
    )
    observations.extend(host_observations)
    findings.extend(host_findings)

    return observations, findings
