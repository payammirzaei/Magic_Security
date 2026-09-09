from __future__ import annotations

import json
import re
from urllib.parse import urljoin

import httpx

from magic_security.models import (
    Finding,
    FindingKind,
    SensitiveEndpointObservation,
    Severity,
)


_SECRET_KEY_RE = re.compile(
    r"(?i)(secret|password|passwd|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|private[_-]?key|database[_-]?url|jwt)"
)


async def _read_prefix(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int = 200_000,
) -> tuple[int, dict[str, str], bytes]:
    try:
        async with client.stream(
            "GET",
            url,
            headers={"Range": f"bytes=0-{max_bytes - 1}"},
        ) as response:
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                remaining = max_bytes - total
                chunks.append(chunk[:remaining])
                total += min(len(chunk), remaining)
                if total >= max_bytes:
                    break
            return (
                response.status_code,
                dict(response.headers),
                b"".join(chunks),
            )
    except httpx.HTTPError:
        return 0, {}, b""


def _json_secret_names(data: object) -> tuple[str, ...]:
    names: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                if _SECRET_KEY_RE.search(key_text):
                    names.add(key_text)
                walk(child)
        elif isinstance(value, list):
            for child in value[:100]:
                walk(child)

    walk(data)
    return tuple(sorted(names))


async def probe_sensitive_endpoints(
    target: str,
    *,
    timeout: float = 5.0,
) -> tuple[list[SensitiveEndpointObservation], list[Finding]]:
    observations: list[SensitiveEndpointObservation] = []
    findings: list[Finding] = []

    probes = (
        (
            "/.svn/entries",
            "source_control_metadata",
            lambda b, h: (
                b.startswith(b"<?xml")
                or b"svn" in b.lower()
                or b"dir\n" in b.lower()
            ),
            Severity.MEDIUM,
        ),
        (
            "/.hg/requires",
            "source_control_metadata",
            lambda b, h: (
                b"revlogv1" in b.lower()
                or b"store" in b.lower()
            ),
            Severity.MEDIUM,
        ),
        (
            "/.DS_Store",
            "filesystem_metadata",
            lambda b, h: b.startswith(b"\x00\x00\x00\x01Bud1"),
            Severity.LOW,
        ),
        (
            "/server-status",
            "server_status",
            lambda b, h: b"apache server status" in b.lower(),
            Severity.MEDIUM,
        ),
        (
            "/phpinfo.php",
            "runtime_debug",
            lambda b, h: (
                b"php version" in b.lower()
                and b"phpinfo()" in b.lower()
            ),
            Severity.HIGH,
        ),
        (
            "/debug/vars",
            "runtime_debug",
            lambda b, h: (
                b"memstats" in b.lower()
                or b"cmdline" in b.lower()
            ),
            Severity.MEDIUM,
        ),
        (
            "/WEB-INF/web.xml",
            "application_config",
            lambda b, h: b"<web-app" in b.lower(),
            Severity.HIGH,
        ),
        (
            "/package.json",
            "dependency_manifest",
            lambda b, h: (
                b'"dependencies"' in b
                or b'"devDependencies"' in b
            ),
            Severity.LOW,
        ),
        (
            "/composer.json",
            "dependency_manifest",
            lambda b, h: (
                b'"require"' in b
                and b"composer" in b.lower()
            ),
            Severity.LOW,
        ),
        (
            "/backup.zip",
            "backup_archive",
            lambda b, h: b.startswith(b"PK\x03\x04"),
            Severity.HIGH,
        ),
        (
            "/site.zip",
            "backup_archive",
            lambda b, h: b.startswith(b"PK\x03\x04"),
            Severity.HIGH,
        ),
        (
            "/www.zip",
            "backup_archive",
            lambda b, h: b.startswith(b"PK\x03\x04"),
            Severity.HIGH,
        ),
        (
            "/database.sql",
            "database_dump",
            lambda b, h: (
                b"create table" in b.lower()
                or b"insert into" in b.lower()
            ),
            Severity.CRITICAL,
        ),
        (
            "/dump.sql",
            "database_dump",
            lambda b, h: (
                b"create table" in b.lower()
                or b"insert into" in b.lower()
            ),
            Severity.CRITICAL,
        ),
    )

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/1.0 exposure-pack",
        },
    ) as client:
        for path, category, matcher, severity in probes:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            status, headers, body = await _read_prefix(client, url)
            verified = bool(status == 200 and matcher(body, headers))

            observations.append(
                SensitiveEndpointObservation(
                    url=url,
                    category=category,
                    status_code=status,
                    verified=verified,
                    detail="signature_matched" if verified else "not_verified",
                )
            )

            if not verified:
                continue

            findings.append(
                Finding(
                    title=(
                        "Sensitive deployment artifact is publicly exposed"
                        if category not in {
                            "runtime_debug",
                            "server_status",
                        }
                        else "Production debug/status endpoint is exposed"
                    ),
                    severity=severity,
                    kind=FindingKind.EXPOSURE,
                    url=url,
                    description=(
                        f"A known {category.replace('_', ' ')} endpoint "
                        "was reachable and matched its expected signature."
                    ),
                    evidence=(
                        "HTTP 200 matched a scanner signature for this "
                        "artifact type. Response contents were not stored."
                    ),
                    remediation=(
                        "Remove the artifact from the public web root or "
                        "restrict access at the application/proxy layer."
                    ),
                    confidence=1.0,
                    cwe="CWE-200",
                )
            )

        for path in ("/config.json", "/actuator/env"):
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            status, headers, body = await _read_prefix(client, url)
            verified = False
            detail = "not_verified"
            secret_names: tuple[str, ...] = ()

            if status == 200:
                try:
                    data = json.loads(body.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    data = None

                if isinstance(data, (dict, list)):
                    secret_names = _json_secret_names(data)
                    if path == "/actuator/env":
                        verified = bool(
                            isinstance(data, dict)
                            and (
                                "propertySources" in data
                                or "activeProfiles" in data
                            )
                        )
                    else:
                        verified = bool(secret_names)

            if verified:
                detail = "json_signature_matched"

            observations.append(
                SensitiveEndpointObservation(
                    url=url,
                    category=(
                        "spring_actuator_env"
                        if path == "/actuator/env"
                        else "public_config"
                    ),
                    status_code=status,
                    verified=verified,
                    detail=detail,
                )
            )

            if not verified:
                continue

            findings.append(
                Finding(
                    title=(
                        "Spring actuator environment endpoint is exposed"
                        if path == "/actuator/env"
                        else "Public configuration exposes secret-like keys"
                    ),
                    severity=(
                        Severity.HIGH
                        if secret_names
                        else Severity.MEDIUM
                    ),
                    kind=FindingKind.EXPOSURE,
                    url=url,
                    description=(
                        "A public JSON configuration/debug endpoint "
                        "revealed environment or secret-like key names."
                    ),
                    evidence=(
                        "Detected secret-like key names: "
                        + (
                            ", ".join(secret_names[:12])
                            if secret_names
                            else "environment metadata"
                        )
                        + ". Values were not stored."
                    ),
                    remediation=(
                        "Restrict the endpoint and rotate any credential "
                        "that may have been publicly exposed."
                    ),
                    confidence=1.0,
                    cwe="CWE-200",
                )
            )

        heapdump_url = urljoin(
            target.rstrip("/") + "/",
            "actuator/heapdump",
        )
        try:
            response = await client.head(heapdump_url)
        except httpx.HTTPError:
            response = None

        heapdump_verified = bool(
            response is not None
            and response.status_code == 200
            and (
                "octet-stream" in response.headers.get(
                    "content-type", ""
                ).lower()
                or int(
                    response.headers.get("content-length", "0") or "0"
                ) > 100_000
            )
        )

        observations.append(
            SensitiveEndpointObservation(
                url=heapdump_url,
                category="heapdump",
                status_code=(
                    response.status_code if response is not None else 0
                ),
                verified=heapdump_verified,
                detail=(
                    "heapdump_response_detected"
                    if heapdump_verified
                    else "not_verified"
                ),
            )
        )

        if heapdump_verified:
            findings.append(
                Finding(
                    title="Application heap dump endpoint is publicly exposed",
                    severity=Severity.CRITICAL,
                    kind=FindingKind.EXPOSURE,
                    url=heapdump_url,
                    description=(
                        "A public heap-dump endpoint was detected. Heap "
                        "dumps can contain credentials, tokens, and user data."
                    ),
                    evidence=(
                        "HEAD returned HTTP 200 with a heap-dump-like "
                        "content type/size. The heap dump was not downloaded."
                    ),
                    remediation=(
                        "Disable public heap-dump access and restrict "
                        "management endpoints to trusted administrative networks."
                    ),
                    confidence=1.0,
                    cwe="CWE-200",
                )
            )

    return observations, findings
