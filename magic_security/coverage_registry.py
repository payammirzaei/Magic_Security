from __future__ import annotations

from magic_security.models import CrawlResult


_CATEGORIES = (
    ("Authentication", "auth"),
    ("Authorization / Access Control", "auth"),
    ("Session Security", "auth"),
    ("SQL / Database", "external"),
    ("Injection", "external"),
    ("XSS", "browser"),
    ("CSRF", "auth"),
    ("SSRF", "config"),
    ("File Upload", "config"),
    ("Path / File Handling", "partial"),
    ("API Security", "external"),
    ("REST / HTTP", "external"),
    ("GraphQL", "external"),
    ("WebSockets", "browser"),
    ("Business Logic", "config"),
    ("Race Conditions", "config"),
    ("Payments", "config"),
    ("Cryptography", "partial"),
    ("Secrets", "external"),
    ("Security Headers", "passive"),
    ("CORS", "external"),
    ("Clickjacking", "passive"),
    ("Redirects / URLs", "external"),
    ("Information Disclosure", "external"),
    ("Error Handling", "external"),
    ("DoS / Resource Exhaustion", "config"),
    ("Rate Limiting", "external"),
    ("Cloud / Infrastructure", "partial"),
    ("Docker / Container", "repo"),
    ("CI/CD", "repo"),
    ("Supply Chain", "repo"),
    ("Frontend", "browser"),
    ("React / Next.js / SPA", "browser"),
    ("Backend Framework", "partial"),
    ("Cache", "external"),
    ("Email", "config"),
    ("Account Takeover", "config"),
    ("Admin Panels", "partial"),
    ("Logging / Monitoring", "repo"),
    ("Privacy / Data Exposure", "external"),
    ("Misconfiguration", "passive"),
    ("AI / LLM features", "config"),
)


def build_coverage_registry(
    crawl: CrawlResult,
    *,
    active: bool,
    browser: bool,
    auth_enabled: bool,
) -> list[dict[str, str]]:
    registry: list[dict[str, str]] = []

    for name, family in _CATEGORIES:
        if family == "auth":
            status = "Fully Tested" if auth_enabled else "Requires Auth"
        elif family == "external":
            status = "Fully Tested" if active else "Passive Only"
        elif family == "browser":
            status = "Fully Tested" if browser else "Partial"
        elif family == "passive":
            status = "Fully Tested"
        elif family == "partial":
            status = "Partial"
        elif family == "repo":
            status = "Requires Repo Access"
        else:
            status = "Requires Config"

        note = ""
        if name == "SQL / Database":
            note = (
                "Error-trigger behavior is tested; exploitability still requires "
                "manual or configured deeper verification."
            )
        elif name == "CSRF":
            note = (
                "Posture is mapped automatically; destructive proof requires an "
                "explicit disposable action configuration."
            )
        elif name == "SSRF":
            note = (
                "Not automatically exploited to avoid unintended access to internal "
                "services. Requires an explicit safe callback/configuration."
            )
        elif name in {"File Upload", "Business Logic", "Race Conditions"}:
            note = "Needs workflow-specific test configuration."
        elif name == "Authorization / Access Control" and auth_enabled:
            note = "Read-only same-role IDOR/BOLA verification is active."
        elif name == "XSS" and browser:
            note = "Reflected and DOM execution can be verified with Playwright."

        registry.append(
            {
                "category": name,
                "status": status,
                "note": note,
            }
        )

    return registry
