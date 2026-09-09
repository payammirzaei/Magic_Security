from __future__ import annotations

import re

import httpx

from magic_security.transport import SecureTransport

from magic_security.models import (
    Finding,
    FindingKind,
    ProtocolSecurityObservation,
    Severity,
)


async def analyze_protocol_security(
    target: str,
    *,
    timeout: float = 5.0,
) -> tuple[list[ProtocolSecurityObservation], list[Finding]]:
    observations: list[ProtocolSecurityObservation] = []
    findings: list[Finding] = []

    async with SecureTransport(
        follow_redirects=False,
        timeout=timeout,
        headers={"User-Agent": "Magic-Security/0.9 local-security-scanner"},
    ) as client:
        try:
            response = await client.get(target)
        except httpx.HTTPError:
            return observations, findings

        server = response.headers.get("server", "").strip()
        powered = response.headers.get("x-powered-by", "").strip()

        for header, value in (("Server", server), ("X-Powered-By", powered)):
            if not value:
                continue
            observations.append(
                ProtocolSecurityObservation(
                    category="server_fingerprint",
                    method="GET",
                    status_code=response.status_code,
                    detail=f"{header} header disclosed product information",
                )
            )
            findings.append(
                Finding(
                    title=f"{header} reveals server technology",
                    severity=Severity.INFO,
                    kind=FindingKind.HARDENING,
                    url=target,
                    description=(
                        "The response exposes server/framework fingerprint information."
                    ),
                    evidence=f"{header} header was present. The exact value is omitted.",
                    remediation=(
                        "Remove unnecessary version/product disclosure where practical."
                    ),
                    confidence=1.0,
                    cwe="CWE-200",
                )
            )

        marker = "magic-security-trace-marker"
        try:
            trace = await client.request(
                "TRACE",
                target,
                headers={
                    "X-Magic-Security-Trace": marker,
                    "User-Agent": "Magic-Security/0.9 local-security-scanner",
                },
            )
        except httpx.HTTPError:
            trace = None

        if trace is not None:
            reflected = marker in trace.text
            enabled = trace.status_code < 400 and reflected
            observations.append(
                ProtocolSecurityObservation(
                    category="trace_method",
                    method="TRACE",
                    status_code=trace.status_code,
                    detail=(
                        "TRACE reflected request data"
                        if enabled
                        else "TRACE not observably enabled"
                    ),
                )
            )

            if enabled:
                findings.append(
                    Finding(
                        title="HTTP TRACE method reflects request data",
                        severity=Severity.LOW,
                        kind=FindingKind.EXPOSURE,
                        url=target,
                        description=(
                            "The server accepted TRACE and reflected a controlled request header."
                        ),
                        evidence=(
                            "TRACE returned the scanner's inert marker. No credentials "
                            "or browser data were sent."
                        ),
                        remediation=(
                            "Disable TRACE unless it is explicitly required."
                        ),
                        confidence=1.0,
                        cwe="CWE-200",
                    )
                )

        try:
            options = await client.options(target)
        except httpx.HTTPError:
            options = None

        if options is not None:
            allow = options.headers.get("allow", "")
            methods = tuple(
                sorted(
                    {
                        item.strip().upper()
                        for item in allow.split(",")
                        if item.strip()
                    }
                )
            )
            observations.append(
                ProtocolSecurityObservation(
                    category="allowed_methods",
                    method="OPTIONS",
                    status_code=options.status_code,
                    detail=(
                        "allowed methods: " + ", ".join(methods)
                        if methods
                        else "no Allow header"
                    ),
                )
            )

            unusual = {
                method
                for method in methods
                if method in {"TRACE", "CONNECT"}
            }
            if unusual:
                findings.append(
                    Finding(
                        title="Potentially dangerous HTTP methods advertised",
                        severity=Severity.LOW,
                        kind=FindingKind.EXPOSURE,
                        url=target,
                        description=(
                            "The server advertises HTTP methods that are rarely required "
                            "for ordinary web applications."
                        ),
                        evidence=(
                            "OPTIONS advertised: " + ", ".join(sorted(unusual))
                        ),
                        remediation=(
                            "Restrict allowed HTTP methods at the application and proxy layers."
                        ),
                        confidence=1.0,
                        cwe="CWE-749",
                    )
                )

    return observations, findings
