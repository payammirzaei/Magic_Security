from __future__ import annotations

from urllib.parse import urlparse

from magic_security.models import Finding, FindingKind, PageSnapshot, Severity


class SecurityHeaderCheck:
    name = "security_headers"

    def run(self, page: PageSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        headers = page.headers

        expected = {
            "content-security-policy": (
                "Content-Security-Policy is not configured.",
                "Add a restrictive CSP appropriate for the application.",
            ),
            "x-content-type-options": (
                "X-Content-Type-Options is not configured.",
                "Set X-Content-Type-Options: nosniff.",
            ),
            "referrer-policy": (
                "Referrer-Policy is not configured.",
                "Set an explicit Referrer-Policy suitable for the application.",
            ),
        }

        for header, (description, remediation) in expected.items():
            if header not in headers:
                findings.append(
                    Finding(
                        title=f"Missing {header}",
                        severity=Severity.INFO,
                        kind=FindingKind.HARDENING,
                        url=page.url,
                        description=description,
                        evidence=f"Response did not contain the {header} header.",
                        remediation=remediation,
                        confidence=1.0,
                    )
                )

        if urlparse(page.url).scheme == "https" and "strict-transport-security" not in headers:
            findings.append(
                Finding(
                    title="Missing Strict-Transport-Security",
                    severity=Severity.LOW,
                    kind=FindingKind.HARDENING,
                    url=page.url,
                    description="HTTPS is in use but HSTS is not configured.",
                    evidence="Strict-Transport-Security header was absent.",
                    remediation="Enable HSTS after confirming the domain is HTTPS-only.",
                    confidence=1.0,
                )
            )

        return findings
