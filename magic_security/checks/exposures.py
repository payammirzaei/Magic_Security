from __future__ import annotations

import re
from urllib.parse import urlparse

from magic_security.models import Finding, FindingKind, PageSnapshot, Severity


class ExposureHeuristicCheck:
    name = "exposure_heuristics"

    _debug_patterns = [
        re.compile(r"traceback \(most recent call last\)", re.I),
        re.compile(r"werkzeug debugger", re.I),
        re.compile(r"django.*debug", re.I),
        re.compile(r"whoops! there was an error", re.I),
        re.compile(r"uncaught (exception|error)", re.I),
    ]

    def run(self, page: PageSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        body = page.body
        path = urlparse(page.url).path.lower()

        if body and re.search(r"<title>\s*index of /", body, re.I):
            findings.append(
                Finding(
                    title="Directory listing is enabled",
                    severity=Severity.MEDIUM,
                    kind=FindingKind.EXPOSURE,
                    url=page.url,
                    description="The web server appears to expose a browsable directory index.",
                    evidence="The response contains an 'Index of /' directory listing signature.",
                    remediation="Disable directory indexing unless it is explicitly required.",
                    confidence=0.99,
                    cwe="CWE-548",
                )
            )

        if any(marker in path for marker in ("/swagger", "/api-docs", "/docs")) and (
            "swagger" in body.lower() or "openapi" in body.lower()
        ):
            findings.append(
                Finding(
                    title="API documentation is publicly exposed",
                    severity=Severity.INFO,
                    kind=FindingKind.EXPOSURE,
                    url=page.url,
                    description="Swagger/OpenAPI documentation appears reachable from the scanned surface.",
                    evidence="The page path and response content both contain API documentation markers.",
                    remediation="Keep public API docs only if intentional; otherwise restrict access in production.",
                    confidence=0.98,
                )
            )

        for pattern in self._debug_patterns:
            match = pattern.search(body)
            if match:
                findings.append(
                    Finding(
                        title="Debug or stack-trace information exposed",
                        severity=Severity.MEDIUM,
                        kind=FindingKind.EXPOSURE,
                        url=page.url,
                        description="The response appears to contain framework or exception debug output.",
                        evidence=f"Matched debug signature: {match.group(0)[:80]!r}.",
                        remediation="Disable debug output in production and return generic error responses.",
                        confidence=0.85,
                        cwe="CWE-209",
                    )
                )
                break

        return findings
