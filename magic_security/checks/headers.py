from __future__ import annotations

from urllib.parse import urlparse

from magic_security.evidence import EvidenceObject, attach_evidence
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
                        evidence=(
                            f"Response did not contain the {header} header."
                        ),
                        remediation=remediation,
                        confidence=1.0,
                        check_id=f"hardening.header.missing.{header}",
                    )
                )

        csp = headers.get("content-security-policy", "")

        if (
            "text/html" in page.content_type
            and "x-frame-options" not in headers
            and "frame-ancestors" not in csp.lower()
        ):
            findings.append(
                Finding(
                    title="Page lacks clickjacking frame protection",
                    severity=Severity.LOW,
                    kind=FindingKind.HARDENING,
                    url=page.url,
                    description=(
                        "The HTML response has no observed anti-framing policy."
                    ),
                    evidence=(
                        "Neither X-Frame-Options nor CSP frame-ancestors was present."
                    ),
                    remediation=(
                        "Set CSP frame-ancestors to the intended embedding policy "
                        "and optionally X-Frame-Options for legacy clients."
                    ),
                    confidence=1.0,
                    cwe="CWE-1021",
                    check_id="browser.clickjacking.missing-protection",
                )
            )

        if csp:
            weak_tokens = [
                token
                for token in ("'unsafe-inline'", "'unsafe-eval'")
                if token in csp.lower()
            ]
            if weak_tokens:
                findings.append(
                    Finding(
                        title="CSP allows risky script execution modes",
                        severity=Severity.LOW,
                        kind=FindingKind.HARDENING,
                        url=page.url,
                        description=(
                            "The Content Security Policy weakens script-injection "
                            "defenses."
                        ),
                        evidence=(
                            "Observed CSP token(s): "
                            + ", ".join(weak_tokens)
                            + "."
                        ),
                        remediation=(
                            "Remove unsafe-inline/unsafe-eval where practical and "
                            "prefer nonces or hashes."
                        ),
                        confidence=1.0,
                        check_id="browser.csp.risky-script-mode",
                    )
                )

        if (
            urlparse(page.url).scheme == "https"
            and "strict-transport-security" not in headers
        ):
            findings.append(
                Finding(
                    title="Missing Strict-Transport-Security",
                    severity=Severity.LOW,
                    kind=FindingKind.HARDENING,
                    url=page.url,
                    description="HTTPS is in use but HSTS is not configured.",
                    evidence="Strict-Transport-Security header was absent.",
                    remediation=(
                        "Enable HSTS after confirming the domain is HTTPS-only."
                    ),
                    confidence=1.0,
                    check_id="hardening.header.missing.strict-transport-security",
                )
            )

        for finding in findings:
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id=finding.check_id or "hardening.header",
                    proof_type="response_header_inspection",
                    baseline_summary="Expected protective header/policy present",
                    mutation_summary="none",
                    observed_result=finding.evidence,
                    confidence=(
                        "verified" if finding.confidence >= 0.95 else "strong"
                    ),
                    sensitive_values_stored=False,
                ),
            )
        return findings
