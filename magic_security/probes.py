from __future__ import annotations

import json
import re
from collections.abc import Iterable
from urllib.parse import urljoin

import httpx

from magic_security.models import Finding, FindingKind, Severity


_SECRET_KEY = re.compile(
    r"(?im)^\s*([A-Z0-9_]*(?:SECRET|PASSWORD|PASS|TOKEN|PRIVATE_KEY|DATABASE_URL|DB_URL|API_KEY)[A-Z0-9_]*)\s*="
)


def _redacted_env_evidence(body: str) -> str:
    names = sorted(set(_SECRET_KEY.findall(body)))
    if names:
        shown = ", ".join(names[:8])
        suffix = " ..." if len(names) > 8 else ""
        return f"Environment-style secret keys were exposed: {shown}{suffix}. Values were redacted."
    return "The response looked like an environment file. Values were not included in the report."


async def probe_common_exposures(target: str, timeout: float = 5.0) -> list[Finding]:
    findings: list[Finding] = []
    probes = ["/.env", "/.git/HEAD", "/openapi.json", "/swagger.json"]

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        for path in probes:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(url, headers={"User-Agent": "Magic-Security/0.2 local-security-scanner"})
            except httpx.HTTPError:
                continue

            if response.status_code != 200:
                continue

            body = response.text[:200_000]

            if path == "/.env":
                matches = _SECRET_KEY.findall(body)
                env_shape = bool(re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=.+$", body))
                if matches or env_shape:
                    findings.append(
                        Finding(
                            title="Environment file is publicly exposed",
                            severity=Severity.CRITICAL if matches else Severity.HIGH,
                            kind=FindingKind.EXPOSURE,
                            url=url,
                            description="A publicly reachable .env response was confirmed.",
                            evidence=_redacted_env_evidence(body),
                            remediation="Block access immediately and rotate every credential that may have been exposed.",
                            confidence=1.0,
                            cwe="CWE-200",
                        )
                    )

            elif path == "/.git/HEAD" and body.lstrip().startswith("ref: refs/"):
                findings.append(
                    Finding(
                        title="Git metadata is publicly exposed",
                        severity=Severity.HIGH,
                        kind=FindingKind.EXPOSURE,
                        url=url,
                        description="The repository HEAD file is reachable over HTTP.",
                        evidence=f"Server returned a Git HEAD reference: {body.strip()[:120]!r}.",
                        remediation="Block access to .git and review whether repository history exposed credentials or sensitive files.",
                        confidence=1.0,
                        cwe="CWE-200",
                    )
                )

            elif path in {"/openapi.json", "/swagger.json"}:
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    continue
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    findings.append(
                        Finding(
                            title="OpenAPI specification is publicly exposed",
                            severity=Severity.INFO,
                            kind=FindingKind.EXPOSURE,
                            url=url,
                            description="A machine-readable API specification is publicly reachable.",
                            evidence=f"HTTP 200 returned JSON containing {'openapi' if 'openapi' in data else 'swagger'} metadata.",
                            remediation="Keep it public only if intentional; otherwise restrict production access.",
                            confidence=1.0,
                        )
                    )

    return findings


async def probe_source_maps(urls: Iterable[str], timeout: float = 5.0) -> list[Finding]:
    findings: list[Finding] = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        for url in sorted(set(urls)):
            try:
                response = await client.get(
                    url,
                    headers={"User-Agent": "Magic-Security/0.2 local-security-scanner"},
                )
            except httpx.HTTPError:
                continue

            if response.status_code != 200:
                continue

            try:
                data = response.json()
            except json.JSONDecodeError:
                continue

            if not isinstance(data, dict) or not isinstance(data.get("sources"), list):
                continue

            source_count = len(data["sources"])
            includes_content = isinstance(data.get("sourcesContent"), list)
            findings.append(
                Finding(
                    title="Frontend source map is publicly exposed",
                    severity=Severity.LOW,
                    kind=FindingKind.EXPOSURE,
                    url=url,
                    description="A valid JavaScript source map is publicly downloadable.",
                    evidence=(
                        f"HTTP 200 returned a valid source map referencing {source_count} source file(s). "
                        f"Embedded source content: {'yes' if includes_content else 'no'}."
                    ),
                    remediation="Disable production source-map publication unless it is intentionally required.",
                    confidence=1.0,
                    cwe="CWE-200",
                )
            )

    return findings
