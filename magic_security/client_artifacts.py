from __future__ import annotations

import json
import re
from collections.abc import Iterable

import httpx

from magic_security.transport import SecureTransport

from magic_security.models import ClientArtifactObservation, Finding, FindingKind, Severity


_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Z0-9_$.-]*(?:secret|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)[A-Z0-9_$.-]*)
    \s*[:=]\s*
    (?P<quote>['"])(?P<value>[^'"]{6,})(?P=quote)
    """
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_INTERNAL_URL_RE = re.compile(
    r"""https?://(?:
        localhost(?::\d+)?
        |127\.0\.0\.1(?::\d+)?
        |10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?
        |192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?
        |172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?
        |[A-Za-z0-9.-]+\.internal(?::\d+)?
    )(?:/[^\s'"<>]*)?""",
    re.IGNORECASE | re.VERBOSE,
)


def _inspect_text(url: str, artifact_type: str, text: str) -> tuple[ClientArtifactObservation, list[Finding]]:
    names = sorted({match.group("name") for match in _SECRET_ASSIGNMENT.finditer(text)})
    token_shapes: list[str] = []
    if _JWT_RE.search(text):
        token_shapes.append("jwt")
    if _PRIVATE_KEY_RE.search(text):
        token_shapes.append("private_key")

    internal_urls = len(set(_INTERNAL_URL_RE.findall(text)))

    observation = ClientArtifactObservation(
        url=url,
        artifact_type=artifact_type,
        secret_like_names=tuple(names[:30]),
        token_shapes=tuple(token_shapes),
        internal_url_count=internal_urls,
    )

    findings: list[Finding] = []

    if names or token_shapes:
        severe = bool(token_shapes) or any(
            any(word in name.lower() for word in ("secret", "password", "private", "access_token", "refresh_token"))
            for name in names
        )
        finding_names = ", ".join(names[:12]) if names else ", ".join(token_shapes)

        findings.append(
            Finding(
                title="Client artifact exposes secret-like material",
                severity=Severity.HIGH if severe else Severity.MEDIUM,
                kind=FindingKind.EXPOSURE,
                url=url,
                description=(
                    "A browser-downloadable JavaScript/source-map artifact contains secret-like assignments "
                    "or credential token shapes."
                ),
                evidence=(
                    f"Detected secret-like identifiers/types: {finding_names}. "
                    "Values were intentionally redacted and not stored."
                ),
                remediation=(
                    "Remove server credentials from frontend bundles/source maps and rotate any real secret "
                    "that has already been published."
                ),
                confidence=1.0,
                cwe="CWE-200",
            )
        )

    if internal_urls:
        findings.append(
            Finding(
                title="Client artifact reveals internal network locations",
                severity=Severity.LOW,
                kind=FindingKind.EXPOSURE,
                url=url,
                description="A browser-downloadable artifact references private/internal network URLs.",
                evidence=f"Detected {internal_urls} unique private/internal URL reference(s); values were not listed.",
                remediation="Remove unnecessary internal topology references from production client artifacts.",
                confidence=1.0,
                cwe="CWE-200",
            )
        )

    return observation, findings


async def analyze_client_artifacts(
    js_assets: Iterable[str],
    source_maps: Iterable[str],
    *,
    timeout: float = 5.0,
    max_assets: int = 40,
) -> tuple[list[ClientArtifactObservation], list[Finding]]:
    observations: list[ClientArtifactObservation] = []
    findings: list[Finding] = []

    assets = [(url, "javascript") for url in sorted(set(js_assets))]
    assets.extend((url, "source_map") for url in sorted(set(source_maps)))

    async with SecureTransport(follow_redirects=False, timeout=timeout) as client:
        for url, artifact_type in assets[:max_assets]:
            try:
                response = await client.get(
                    url,
                    headers={"User-Agent": "Magic-Security/0.7 local-security-scanner"},
                )
            except httpx.HTTPError:
                continue

            if response.status_code != 200:
                continue

            text = response.text[:1_000_000]
            if artifact_type == "source_map":
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    data = None
                if isinstance(data, dict) and isinstance(data.get("sourcesContent"), list):
                    text = "\n".join(
                        item for item in data["sourcesContent"][:100] if isinstance(item, str)
                    )[:1_000_000]

            observation, artifact_findings = _inspect_text(url, artifact_type, text)
            observations.append(observation)
            findings.extend(artifact_findings)

    return observations, findings
