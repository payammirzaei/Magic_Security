from __future__ import annotations

from magic_security.models import CrawlResult


_CATEGORIES = (
    ("Authentication", "auth"),
    ("Authorization / Access Control", "auth"),
    ("Session Security", "auth"),
    ("SQL / Database", "server"),
    ("Injection", "external"),
    ("XSS", "browser"),
    ("CSRF", "auth"),
    ("SSRF", "server"),
    ("File Upload", "config"),
    ("Path / File Handling", "server"),
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
    ("Misconfiguration", "external"),
    ("AI / LLM features", "config"),
)


def _status_for(
    family: str,
    *,
    active: bool,
    browser: bool,
    auth_enabled: bool,
) -> str:
    if family == "auth":
        return "Partially Tested" if auth_enabled else "Requires Auth"
    if family == "external":
        return "Partially Tested" if active else "Passive Only"
    if family == "browser":
        return "Partially Tested" if browser else "Partial"
    if family == "server":
        return "Partially Tested" if active else "Passive Only"
    if family == "passive":
        return "Partially Tested"
    if family == "repo":
        return "Requires Repo Access"
    if family == "config":
        return "Requires Config"
    return "Partial"


def build_coverage_registry(
    crawl: CrawlResult,
    *,
    active: bool,
    browser: bool,
    auth_enabled: bool,
) -> list[dict[str, str]]:
    registry: list[dict[str, str]] = []

    for name, family in _CATEGORIES:
        status = _status_for(
            family,
            active=active,
            browser=browser,
            auth_enabled=auth_enabled,
        )
        note = ""

        if name == "Authentication":
            note = (
                "Auth boundaries, login/token behavior, SQL/NoSQL auth-bypass "
                "signals and rate behavior are tested when discoverable. "
                "Password-reset/MFA/business workflows still need configuration."
            )
        elif name == "Authorization / Access Control":
            note = (
                "Same-role read-only path/query IDOR/BOLA is verified with "
                "test accounts. Complex workflow and state-changing authorization "
                "remain configuration-driven."
            )
        elif name == "Session Security":
            note = (
                "Cookie attributes and authenticated cache behavior are tested. "
                "Login-time rotation/fixation and logout invalidation require "
                "explicit disposable workflow configuration."
            )
        elif name == "SQL / Database":
            note = (
                "Database-error behavior plus SQL/NoSQL login-bypass proofs are "
                "tested when relevant endpoints are discovered; this is not "
                "exhaustive SQLi coverage."
            )
        elif name == "CSRF":
            note = (
                "Cookie/header auth posture and token signals are mapped. "
                "State-changing proof requires an explicitly configured disposable action."
            )
        elif name == "SSRF":
            note = (
                "URL-like GET parameters are tested only against a scanner-owned "
                "127.0.0.1 callback. Cloud metadata/private services are not probed."
            )
        elif name == "File Upload":
            note = (
                "Upload security needs a disposable workflow definition so files "
                "can be safely created, retrieved, and removed."
            )
        elif name == "Path / File Handling":
            note = (
                "Traversal candidates use known non-secret marker files; public "
                "backup/config/deployment artifacts are also signature-probed."
            )
        elif name == "WebSockets":
            note = (
                "Endpoints and mixed ws:// usage are discovered. Full origin/auth "
                "handshake and message authorization testing needs a realtime workflow pack."
            )
        elif name == "Business Logic":
            note = "Requires explicit user journeys, invariants, and disposable test data."
        elif name == "Race Conditions":
            note = "Requires explicit idempotent/disposable concurrent workflows."
        elif name == "Payments":
            note = "Requires sandbox payment flows and business invariants."
        elif name == "XSS":
            note = (
                "Reflected and DOM execution can be verified with Playwright; "
                "stored XSS requires a configured write/read workflow."
            )
        elif name == "Information Disclosure":
            note = (
                "Covers unauthenticated JSON, source maps, client artifacts, "
                "debug/status endpoints, backup archives, config files, heapdump "
                "exposure and sensitive URL parameters."
            )
        elif name == "Privacy / Data Exposure":
            note = (
                "Covers sensitive JSON fields, sensitive URL/query exposure, "
                "GET-form leakage and authenticated cross-account reads."
            )
        elif name == "Misconfiguration":
            note = (
                "Covers headers, CORS, debug/status endpoints, source-control "
                "metadata, dependency manifests, backups and management endpoints."
            )
        elif name == "Frontend":
            note = (
                "Covers DOM XSS signals, storage keys, postMessage, client redirects, "
                "mixed content, sensitive URLs, source maps and WebSocket discovery."
            )
        elif name == "Admin Panels":
            note = (
                "robots.txt/sitemap.xml and discovered routes can reveal hidden admin "
                "surfaces, but admin authorization workflows are not assumed."
            )
        elif name == "Account Takeover":
            note = (
                "Needs configured password-reset/MFA/session-rotation workflows "
                "to prove takeover paths safely."
            )

        registry.append(
            {
                "category": name,
                "status": status,
                "note": note,
            }
        )

    return registry
