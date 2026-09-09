"""Authentication Security Pack v2 (STEP 28)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from magic_security.auth import map_auth_boundaries
from magic_security.behavior_security import (
    analyze_authenticated_cache,
    verify_protected_cors,
)
from magic_security.coverage import build_auth_security_coverage
from magic_security.csrf import map_csrf_posture
from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.models import (
    AuthContext,
    CrawlResult,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.session_security import analyze_session_cookies
from magic_security.transport import open_secure_transport


@dataclass
class AuthSecurityPackResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)


_LOGIN_CANDIDATES = (
    "/login",
    "/api/login",
    "/auth/login",
    "/api/auth/login",
    "/signin",
    "/api/signin",
    "/token",
    "/api/token",
    "/oauth/token",
)


async def _invalid_credential_baseline(
    target: str,
) -> list[Finding]:
    findings: list[Finding] = []
    async with open_secure_transport(follow_redirects=False, timeout=5.0) as client:
        for path in _LOGIN_CANDIDATES[:6]:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.post(
                    url,
                    json={
                        "username": "magic-security-invalid-user",
                        "password": "magic-security-invalid-pass",
                    },
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                )
            except httpx.HTTPError:
                continue
            if response.status_code == 404:
                continue
            findings.append(
                Finding(
                    title="Invalid credential baseline observed",
                    severity=Severity.INFO,
                    kind=FindingKind.HARDENING,
                    url=url,
                    description=(
                        "Synthetic invalid credentials were rejected or "
                        "handled by a login-like endpoint (no guessing)."
                    ),
                    evidence=(
                        f"HTTP {response.status_code}; body_len="
                        f"{len(response.content)}. Credentials were synthetic "
                        "and not reused."
                    ),
                    remediation=(
                        "Keep uniform failure responses for invalid logins."
                    ),
                    confidence=0.8,
                    check_id="auth.invalid-credential.baseline",
                )
            )
            attach_evidence(
                findings[-1],
                EvidenceObject(
                    check_id="auth.invalid-credential.baseline",
                    proof_type="synthetic_invalid_login",
                    baseline_summary="Synthetic invalid credentials only",
                    mutation_summary="Single non-guessing login probe",
                    observed_result=findings[-1].evidence,
                    confidence="likely",
                    sensitive_values_stored=False,
                ),
            )
            break
    return findings


async def _account_enumeration_signal(
    target: str,
) -> list[Finding]:
    """Differential response signal only — no wordlist."""
    findings: list[Finding] = []
    path = "/api/login"
    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    async with open_secure_transport(follow_redirects=False, timeout=5.0) as client:
        try:
            missing = await client.post(
                url,
                json={
                    "username": "magic-security-missing-user",
                    "password": "x",
                },
                headers={"Content-Type": "application/json"},
            )
            malformed = await client.post(
                url,
                json={"username": "", "password": ""},
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError:
            return findings

        if missing.status_code == 404 and malformed.status_code == 404:
            return findings

        if (
            missing.status_code != malformed.status_code
            or abs(len(missing.content) - len(malformed.content)) > 40
        ):
            finding = Finding(
                title="Possible account enumeration via login differentials",
                severity=Severity.LOW,
                kind=FindingKind.EXPOSURE,
                url=url,
                description=(
                    "Login-like responses differed across synthetic probes "
                    "in status or body length (enumeration signal)."
                ),
                evidence=(
                    f"status_a={missing.status_code} len_a={len(missing.content)}; "
                    f"status_b={malformed.status_code} len_b={len(malformed.content)}. "
                    "Not a verified auth bypass."
                ),
                remediation=(
                    "Return uniform responses for unknown users and bad input."
                ),
                confidence=0.75,
                check_id="auth.enumeration.signal",
            )
            attach_evidence(
                finding,
                EvidenceObject(
                    check_id="auth.enumeration.signal",
                    proof_type="login_differential_observation",
                    baseline_summary="Synthetic missing-user probe",
                    mutation_summary="Synthetic empty-credential probe",
                    observed_result=finding.evidence,
                    confidence="likely",
                    sensitive_values_stored=False,
                ),
            )
            findings.append(finding)
    return findings


async def _alternate_auth_endpoints(target: str) -> list[Finding]:
    findings: list[Finding] = []
    async with open_secure_transport(follow_redirects=False, timeout=5.0) as client:
        for path in _LOGIN_CANDIDATES:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            if response.status_code == 404:
                continue
            if response.status_code not in {200, 401, 403, 405}:
                continue
            findings.append(
                Finding(
                    title="Alternate authentication endpoint discovered",
                    severity=Severity.INFO,
                    kind=FindingKind.HARDENING,
                    url=url,
                    description="A login/token-like endpoint responded.",
                    evidence=f"HTTP {response.status_code} for {path}",
                    remediation="Inventory and harden all auth entry points.",
                    confidence=0.7,
                    check_id="auth.endpoint.alternate",
                )
            )
            attach_evidence(
                findings[-1],
                EvidenceObject(
                    check_id="auth.endpoint.alternate",
                    proof_type="auth_endpoint_discovery",
                    baseline_summary="Common auth path probe",
                    mutation_summary="Safe GET discovery only",
                    observed_result=findings[-1].evidence,
                    confidence="candidate",
                    sensitive_values_stored=False,
                ),
            )
    return findings[:8]


async def run_auth_security_pack(
    crawl: CrawlResult,
    contexts: list[AuthContext],
) -> AuthSecurityPackResult:
    result = AuthSecurityPackResult()
    exercised: list[str] = []
    findings: list[Finding] = []

    findings.extend(await _invalid_credential_baseline(crawl.target))
    exercised.append("invalid_credential_baseline")

    findings.extend(await _account_enumeration_signal(crawl.target))
    exercised.append("account_enumeration_signal")

    findings.extend(await _alternate_auth_endpoints(crawl.target))
    exercised.append("alternate_auth_endpoints")

    if not crawl.auth_comparisons:
        crawl.auth_comparisons = await map_auth_boundaries(
            crawl.normalized_endpoints,
            contexts,
        )
    exercised.append("auth_boundaries")

    (
        crawl.session_cookie_observations,
        session_findings,
    ) = await analyze_session_cookies(
        crawl.normalized_endpoints,
        contexts,
    )
    findings.extend(session_findings)
    exercised.append("session_cookies")

    crawl.csrf_candidates = map_csrf_posture(
        crawl.normalized_endpoints,
        contexts,
    )
    exercised.append("csrf_posture")

    (
        crawl.cors_impact_observations,
        protected_cors_findings,
    ) = await verify_protected_cors(
        crawl.auth_comparisons,
        contexts,
    )
    findings.extend(protected_cors_findings)
    exercised.append("protected_cors")

    (
        crawl.cache_observations,
        cache_findings,
    ) = await analyze_authenticated_cache(
        crawl.auth_comparisons,
        contexts,
    )
    findings.extend(cache_findings)
    exercised.append("authenticated_cache")
    exercised.append("session_establishment")

    crawl.auth_security_coverage = build_auth_security_coverage(
        crawl.normalized_endpoints,
        crawl.auth_comparisons,
        crawl.ownership_observations,
        crawl.pairwise_idor_observations,
        crawl.csrf_candidates,
        crawl.session_cookie_observations,
    )

    result.findings = findings
    result.coverage = {
        "pack": "auth_security_v2",
        "exercised": exercised,
        "findings": len(findings),
        "enumeration_kind_policy": "exposure_unless_bypass_proven",
    }
    return result
