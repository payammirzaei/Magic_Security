from __future__ import annotations


import pytest

from magic_security.active import verify_cors
from magic_security.checks.headers import SecurityHeaderCheck
from magic_security.evidence import evidence_from_finding
from magic_security.historical import seed_historical_endpoints
from magic_security.js_analysis import analyze_javascript
from magic_security.logging_metrics import StructuredLogger
from magic_security.models import (
    CrawlResult,
    EndpointCandidate,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    PageSnapshot,
    Severity,
)
from magic_security.pack_runner import run_isolated
from magic_security.registry import CheckStatus, build_default_registry
from magic_security.surface import canonical_endpoint_url, normalize_endpoints
from magic_security.surface_graph import build_attack_surface_graph


def test_evidence_object_from_three_families():
    page = PageSnapshot(
        url="http://127.0.0.1/",
        status_code=200,
        headers={},
        set_cookies=[],
        content_type="text/html",
        body="<html></html>",
    )
    header_findings = SecurityHeaderCheck().run(page)
    assert header_findings
    evidence = evidence_from_finding(header_findings[0])
    assert evidence.check_id
    assert evidence.sensitive_values_stored is False
    assert evidence.proof_type


@pytest.mark.asyncio
async def test_cors_emits_structured_evidence(monkeypatch):
    import httpx

    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={
                "Access-Control-Allow-Origin": "https://magic-security.invalid",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    findings = await verify_cors(["http://localhost/api/me"])
    assert findings
    evidence = evidence_from_finding(findings[0])
    assert evidence.check_id == "cors.arbitrary-origin"
    assert evidence.proof_type == "reflected_acao_origin"


def test_check_registry_lists_and_resolves_profile():
    registry = build_default_registry()
    ids = {item.spec.check_id for item in registry.list_checks()}
    assert "hardening.header.missing" in ids
    assert "authorization.bola.read" in ids

    selected = registry.resolve_for_profile(
        active=False,
        browser=False,
        auth_enabled=False,
    )
    selected_ids = {item.spec.check_id for item in selected}
    assert "hardening.header.missing" in selected_ids
    auth_item = registry.get("authorization.bola.read")
    assert auth_item is not None
    assert auth_item.status is CheckStatus.SKIPPED_AUTH


@pytest.mark.asyncio
async def test_pack_isolation_survives_crashing_check():
    registry = build_default_registry()

    async def boom() -> list[Finding]:
        raise RuntimeError("intentional pack crash")

    async def ok() -> list[Finding]:
        return [
            Finding(
                title="ok",
                severity=Severity.INFO,
                kind=FindingKind.HARDENING,
                url="http://127.0.0.1/",
                description="ok",
                evidence="ok",
                remediation="n/a",
                check_id="test.ok",
            )
        ]

    crashed = await run_isolated(
        pack="test",
        check_id="test.crash",
        coro_factory=boom,
        registry=registry,
    )
    assert crashed.failures
    assert crashed.findings == []

    good = await run_isolated(
        pack="test",
        check_id="test.ok",
        coro_factory=ok,
        registry=registry,
    )
    assert good.findings
    assert not good.failures


def test_structured_logger_redacts_secrets():
    logger = StructuredLogger()
    logger.check_error(
        "demo",
        "password=SuperSecretPassword123! token=reset-token-ABCDEF",
    )
    blob = logger.dumps()
    assert "SuperSecretPassword123!" not in blob
    assert "reset-token-ABCDEF" not in blob


def test_attack_surface_graph_answers_basic_questions():
    crawl = CrawlResult(target="http://127.0.0.1:8000")
    crawl.pages.append(
        PageSnapshot(
            url="http://127.0.0.1:8000/",
            status_code=200,
            headers={},
            set_cookies=[],
            content_type="text/html",
            body="",
        )
    )
    crawl.normalized_endpoints = [
        NormalizedEndpoint(
            url="http://127.0.0.1:8000/api/users",
            method="GET",
            parameters=("id",),
            sources=("html:link",),
        )
    ]
    graph = build_attack_surface_graph(crawl)
    params = graph.parameters_for_endpoint("GET", "http://127.0.0.1:8000/api/users")
    assert "id" in params


def test_normalization_merges_ids_without_false_method_merge():
    endpoints = {
        EndpointCandidate(
            url="http://localhost/api/users/123",
            method="GET",
            source="a",
        ),
        EndpointCandidate(
            url="http://localhost/api/users/456",
            method="GET",
            source="b",
        ),
        EndpointCandidate(
            url="http://localhost/api/users/123",
            method="POST",
            source="c",
        ),
        EndpointCandidate(
            url="http://localhost/api/users?_=cache",
            method="GET",
            source="d",
            parameters=("_", "q"),
        ),
    }
    result = normalize_endpoints(endpoints)
    urls = {(item.method, item.url) for item in result}
    assert ("GET", "http://localhost/api/users/{id}") in urls
    assert ("POST", "http://localhost/api/users/{id}") in urls
    next(item for item in result if item.method == "GET" and item.url.endswith("/users/{id}") or item.url.endswith("/users"))
    # cache bust dropped from params on the plain /users merge candidate
    plain = [item for item in result if item.url == "http://localhost/api/users"]
    if plain:
        assert "_" not in plain[0].parameters


def test_normalization_false_split_locale_and_uuid():
    assert "{uuid}" in canonical_endpoint_url(
        "http://localhost/items/11111111-1111-4111-8111-111111111111"
    )
    assert "{locale}" in canonical_endpoint_url("http://localhost/en-us/dashboard")


def test_historical_seeding_marks_missing_routes():
    current = [
        NormalizedEndpoint(
            url="http://127.0.0.1:8000/api/alive",
            method="GET",
            parameters=(),
            sources=("http",),
        )
    ]
    snapshot = {
        "attack_surface": {
            "items": [
                "endpoint:GET:http://127.0.0.1:8000/api/stale:id",
                "endpoint:GET:http://127.0.0.1:8000/api/alive:",
            ]
        }
    }
    merged, seeded = seed_historical_endpoints(current, snapshot)
    assert any(item.url.endswith("/api/stale") for item in seeded)
    assert all("historical:snapshot" in item.sources for item in seeded)
    assert len(merged) == 2


def test_js_analysis_v2_extracts_structured_literals():
    text = """
    const api = '/api/v1/orders';
    const gql = '/graphql';
    const ws = 'wss://127.0.0.1:8000/ws';
    const route = '/dashboard/settings';
    window.addEventListener('message', () => {});
    el.innerHTML = location.search;
    const apiKey = 'sk_live_abcdefghijklmnopqrstuv';
    //# sourceMappingURL=app.js.map
    """
    result = analyze_javascript(text, "http://127.0.0.1:8000/static/app.js")
    assert result.confidence == "structured"
    assert any("/api/v1/orders" in path for path in result.api_paths)
    assert result.graphql_paths
    assert result.websocket_urls
    assert result.client_routes
    assert result.postmessage_handlers >= 1
    assert result.dangerous_sinks
    assert result.browser_sources
    assert result.secret_like_names
    assert "sk_live_abcdefghijklmnopqrstuv" not in str(result.to_dict())
