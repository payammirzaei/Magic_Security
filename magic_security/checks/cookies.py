from __future__ import annotations

from urllib.parse import urlparse

from magic_security.models import Finding, FindingKind, PageSnapshot, Severity


class CookieSecurityCheck:
    name = "cookie_security"

    def run(self, page: PageSnapshot) -> list[Finding]:
        findings: list[Finding] = []
        is_https = urlparse(page.url).scheme == "https"

        for raw_cookie in page.set_cookies:
            first = raw_cookie.split(";", 1)[0]
            cookie_name = first.split("=", 1)[0].strip() or "<unknown>"
            lower = raw_cookie.lower()

            missing: list[str] = []
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if "samesite=" not in lower:
                missing.append("SameSite")
            if is_https and "secure" not in lower:
                missing.append("Secure")

            if not missing:
                continue

            findings.append(
                Finding(
                    title=f"Cookie {cookie_name} is missing security attributes",
                    severity=Severity.LOW,
                    kind=FindingKind.HARDENING,
                    url=page.url,
                    description=f"The cookie is missing: {', '.join(missing)}.",
                    evidence=f"Set-Cookie for {cookie_name} lacked {', '.join(missing)}. Cookie value is intentionally redacted.",
                    remediation="Add the appropriate Secure, HttpOnly, and SameSite attributes based on the cookie purpose.",
                    confidence=1.0,
                )
            )

        return findings
