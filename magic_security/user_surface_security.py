from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import parse_qsl, urlsplit

import httpx
from bs4 import BeautifulSoup

from magic_security.models import (
    Finding,
    FindingKind,
    NormalizedEndpoint,
    PageSnapshot,
    Severity,
    UserSurfaceObservation,
)


_SECRET_URL_PARAMS = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "jwt",
    "session",
    "session_id",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "otp",
    "code",
    "reset_token",
    "verification_token",
}
_PII_URL_PARAMS = {
    "email",
    "phone",
    "mobile",
    "address",
    "iban",
    "card_number",
    "credit_card",
    "cvv",
}
_SENSITIVE_FORM_PARAMS = (
    _SECRET_URL_PARAMS
    | _PII_URL_PARAMS
    | {"password_confirmation", "new_password"}
)
_JSONP_PARAMS = {"callback", "jsonp", "cb"}
_PROBE_ORIGIN = "null"
_JSONP_CALLBACK = "magicSecurityCallback"


def _sensitive_url_parameters(url: str) -> tuple[str, ...]:
    parts = urlsplit(url)
    names = {
        key.lower()
        for key, value in parse_qsl(
            parts.query,
            keep_blank_values=True,
        )
        if value
    }
    if parts.fragment and "=" in parts.fragment:
        names.update(
            key.lower()
            for key, value in parse_qsl(
                parts.fragment,
                keep_blank_values=True,
            )
            if value
        )
    return tuple(
        sorted(names & (_SECRET_URL_PARAMS | _PII_URL_PARAMS))
    )


def analyze_user_visible_surface(
    *,
    target: str,
    pages: list[PageSnapshot],
    links: Iterable[str],
    endpoints: list[NormalizedEndpoint],
) -> tuple[list[UserSurfaceObservation], list[Finding]]:
    observations: list[UserSurfaceObservation] = []
    findings: list[Finding] = []
    seen_url_params: set[tuple[str, str]] = set()

    candidate_urls = set(links)
    candidate_urls.update(endpoint.url for endpoint in endpoints)
    candidate_urls.update(page.url for page in pages)

    for url in sorted(candidate_urls):
        for parameter in _sensitive_url_parameters(url):
            key = (urlsplit(url)._replace(query="", fragment="").geturl(), parameter)
            if key in seen_url_params:
                continue
            seen_url_params.add(key)

            secret_like = parameter in _SECRET_URL_PARAMS
            observations.append(
                UserSurfaceObservation(
                    category="sensitive_url_parameter",
                    url=key[0],
                    parameter=parameter,
                    verified=True,
                    detail="secret_like" if secret_like else "pii_like",
                )
            )
            findings.append(
                Finding(
                    title=(
                        "Secret/authentication material appears in URL"
                        if secret_like
                        else "Personal/payment data appears in URL"
                    ),
                    severity=(
                        Severity.HIGH if secret_like else Severity.MEDIUM
                    ),
                    kind=FindingKind.EXPOSURE,
                    url=key[0],
                    description=(
                        f"Parameter {parameter!r} was observed with a value "
                        "in a URL. URLs can leak through browser history, "
                        "logs, analytics, screenshots, and referrers."
                    ),
                    evidence=(
                        f"Observed populated URL parameter name: "
                        f"{parameter}. The parameter value was not stored."
                    ),
                    remediation=(
                        "Move sensitive values to request bodies or secure "
                        "cookies/headers and avoid placing credentials or PII in URLs."
                    ),
                    confidence=1.0,
                    cwe="CWE-598",
                )
            )

    for endpoint in endpoints:
        if endpoint.method.upper() != "GET":
            continue
        if not any("form" in source for source in endpoint.sources):
            continue

        sensitive = sorted(
            {
                parameter
                for parameter in endpoint.parameters
                if parameter.lower() in _SENSITIVE_FORM_PARAMS
            }
        )
        if not sensitive:
            continue

        observations.append(
            UserSurfaceObservation(
                category="sensitive_get_form",
                url=endpoint.url,
                parameter=",".join(sensitive),
                verified=True,
                detail="sensitive_fields_submitted_with_get",
            )
        )
        findings.append(
            Finding(
                title="Sensitive form fields are submitted with GET",
                severity=Severity.HIGH,
                kind=FindingKind.EXPOSURE,
                url=endpoint.url,
                description=(
                    "A discovered GET form contains credential, token, "
                    "personal, or payment-like field names."
                ),
                evidence=(
                    "Sensitive field names: "
                    + ", ".join(sensitive[:12])
                    + ". Values were not captured."
                ),
                remediation=(
                    "Submit sensitive forms with POST over HTTPS and keep "
                    "secret values out of query strings."
                ),
                confidence=1.0,
                cwe="CWE-598",
            )
        )

    if urlsplit(target).scheme.lower() == "https":
        for page in pages:
            if "html" not in page.content_type.lower():
                continue
            soup = BeautifulSoup(page.body, "html.parser")
            insecure: set[str] = set()

            for tag, attr in (
                ("script", "src"),
                ("img", "src"),
                ("iframe", "src"),
                ("link", "href"),
                ("source", "src"),
                ("video", "src"),
                ("audio", "src"),
                ("form", "action"),
            ):
                for node in soup.find_all(tag):
                    value = str(node.get(attr) or "").strip()
                    if value.lower().startswith("http://"):
                        insecure.add(f"{tag}.{attr}")

            if not insecure:
                continue

            observations.append(
                UserSurfaceObservation(
                    category="mixed_content",
                    url=page.url,
                    parameter=None,
                    verified=True,
                    detail=",".join(sorted(insecure)),
                )
            )
            findings.append(
                Finding(
                    title="HTTPS page references insecure HTTP resources",
                    severity=Severity.MEDIUM,
                    kind=FindingKind.EXPOSURE,
                    url=page.url,
                    description=(
                        "An HTTPS page references one or more resources "
                        "or form actions over plaintext HTTP."
                    ),
                    evidence=(
                        "Insecure element types: "
                        + ", ".join(sorted(insecure))
                        + ". Resource URLs were not listed."
                    ),
                    remediation=(
                        "Load all active/passive resources and submit all "
                        "forms over HTTPS only."
                    ),
                    confidence=1.0,
                    cwe="CWE-319",
                )
            )

    return observations, findings


def _set_query(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    pairs = [
        (key, current)
        for key, current in parse_qsl(
            parts.query,
            keep_blank_values=True,
        )
        if key != parameter
    ]
    pairs.append((parameter, value))
    from urllib.parse import urlencode, urlunsplit

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(pairs),
            parts.fragment,
        )
    )


async def verify_jsonp_and_null_origin_cors(
    endpoints: list[NormalizedEndpoint],
    *,
    timeout: float = 5.0,
    max_tests: int = 30,
) -> tuple[list[UserSurfaceObservation], list[Finding]]:
    observations: list[UserSurfaceObservation] = []
    findings: list[Finding] = []
    tested = 0

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        headers={
            "User-Agent": "Magic-Security/1.0 user-surface",
        },
    ) as client:
        for endpoint in endpoints:
            if tested >= max_tests:
                break
            if endpoint.method.upper() != "GET":
                continue
            if "{" in endpoint.url or "}" in endpoint.url:
                continue

            tested += 1
            try:
                cors = await client.get(
                    endpoint.url,
                    headers={"Origin": _PROBE_ORIGIN},
                )
            except httpx.HTTPError:
                cors = None

            if cors is not None:
                allow_origin = cors.headers.get(
                    "access-control-allow-origin",
                    "",
                ).strip().lower()
                credentials = cors.headers.get(
                    "access-control-allow-credentials",
                    "",
                ).strip().lower() == "true"
                accepted = allow_origin == "null"

                observations.append(
                    UserSurfaceObservation(
                        category="null_origin_cors",
                        url=endpoint.url,
                        parameter=None,
                        verified=accepted,
                        detail=(
                            "credentials_allowed"
                            if accepted and credentials
                            else (
                                "origin_allowed"
                                if accepted
                                else "not_allowed"
                            )
                        ),
                    )
                )

                if accepted:
                    findings.append(
                        Finding(
                            title=(
                                "CORS accepts null Origin with credentials"
                                if credentials
                                else "CORS accepts null Origin"
                            ),
                            severity=(
                                Severity.HIGH
                                if credentials
                                else Severity.MEDIUM
                            ),
                            kind=FindingKind.EXPOSURE,
                            url=endpoint.url,
                            description=(
                                "The endpoint explicitly allows the null "
                                "Origin used by sandboxed/file-like browser contexts."
                            ),
                            evidence=(
                                "Origin: null was returned in "
                                "Access-Control-Allow-Origin; credentials="
                                + ("true" if credentials else "false")
                                + "."
                            ),
                            remediation=(
                                "Do not allow the null Origin unless a "
                                "specific, reviewed use case requires it."
                            ),
                            confidence=1.0,
                            cwe="CWE-942",
                        )
                    )

            jsonp_parameters = [
                parameter
                for parameter in endpoint.parameters
                if parameter.lower() in _JSONP_PARAMS
            ]
            for parameter in jsonp_parameters:
                try:
                    response = await client.get(
                        _set_query(
                            endpoint.url,
                            parameter,
                            _JSONP_CALLBACK,
                        )
                    )
                except httpx.HTTPError:
                    continue

                body = response.text.lstrip()[:300_000]
                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()
                wrapped = bool(
                    response.status_code == 200
                    and body.startswith(_JSONP_CALLBACK + "(")
                    and (
                        "javascript" in content_type
                        or "json" in content_type
                        or "text/plain" in content_type
                    )
                )

                observations.append(
                    UserSurfaceObservation(
                        category="jsonp",
                        url=endpoint.url,
                        parameter=parameter,
                        verified=wrapped,
                        detail=(
                            "arbitrary_callback_wrapping"
                            if wrapped
                            else "not_verified"
                        ),
                    )
                )

                if wrapped:
                    findings.append(
                        Finding(
                            title="JSONP-style arbitrary callback wrapping verified",
                            severity=Severity.MEDIUM,
                            kind=FindingKind.EXPOSURE,
                            url=endpoint.url,
                            description=(
                                "A caller-controlled callback name was used "
                                "to wrap the endpoint response as executable JavaScript."
                            ),
                            evidence=(
                                f"Parameter {parameter!r} accepted the "
                                "scanner callback identifier. Response data "
                                "was not stored and no script was executed."
                            ),
                            remediation=(
                                "Prefer CORS-protected JSON APIs instead of "
                                "JSONP, especially for authenticated or sensitive data."
                            ),
                            confidence=1.0,
                            cwe="CWE-79",
                        )
                    )

    return observations, findings
