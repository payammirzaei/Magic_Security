"""Tests for STEPs 21–30 pack consolidation."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from magic_security.api_security import run_api_security_pack
from magic_security.auth import load_auth_contexts
from magic_security.auth_context import validate_auth_identities
from magic_security.auth_security import run_auth_security_pack
from magic_security.authz_matrix import build_authz_matrix
from magic_security.browser_pack import run_browser_pack
from magic_security.evidence import EvidenceObject, attach_evidence
from magic_security.exposure_pack_v2 import run_exposure_pack_v2
from magic_security.graphql_pack import run_graphql_pack
from magic_security.graphql_security import build_depth_query
from magic_security.models import (
    AuthComparison,
    AuthContext,
    CrawlResult,
    EndpointCandidate,
    Finding,
    FindingKind,
    NormalizedEndpoint,
    PairwiseIdorObservation,
    Severity,
)
from magic_security.registry import build_default_registry
from magic_security.server_pack import run_server_pack
from magic_security.websocket_security import (
    WebsocketConnectResult,
    run_websocket_pack,
)


@pytest.mark.asyncio
async def test_exposure_pack_v2_never_emits_high_hardening(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    crawl = CrawlResult(target="http://127.0.0.1:9/")
    result = await run_exposure_pack_v2(crawl, active=False)
    assert result.coverage["pack"] == "exposure_v2"
    assert result.coverage["high_hardening_count"] == 0
    for finding in result.findings:
        if finding.kind is FindingKind.HARDENING:
            assert finding.severity not in {Severity.HIGH, Severity.CRITICAL}
        if finding.structured_evidence:
            assert finding.structured_evidence["sensitive_values_stored"] is False


@pytest.mark.asyncio
async def test_browser_pack_candidate_vs_verified():
    crawl = CrawlResult(target="http://127.0.0.1/")
    candidate = Finding(
        title="Possible client redirect sink",
        severity=Severity.LOW,
        kind=FindingKind.HARDENING,
        url="http://127.0.0.1/app.js",
        description="Static sink observation",
        evidence="location.href assignment seen",
        remediation="Validate redirects",
        confidence=0.4,
        check_id="browser.redirect.static",
    )
    attach_evidence(
        candidate,
        EvidenceObject(
            check_id="browser.redirect.static",
            proof_type="static_sink",
            observed_result="candidate only",
            confidence="candidate",
        ),
    )
    verified = Finding(
        title="DOM XSS execution",
        severity=Severity.HIGH,
        kind=FindingKind.VULNERABILITY,
        url="http://127.0.0.1/",
        description="Canary executed",
        evidence="canary fired",
        remediation="Encode sinks",
        confidence=1.0,
        check_id="xss.dom.execution",
    )
    attach_evidence(
        verified,
        EvidenceObject(
            check_id="xss.dom.execution",
            proof_type="runtime_canary_execution",
            observed_result="canary",
            confidence="verified",
        ),
    )
    assert not candidate.verified
    assert verified.verified
    result = await run_browser_pack(crawl, active=False, browser=False)
    assert "static_artifacts" in result.coverage["exercised"]
    assert "dom_xss" in result.coverage["skipped"]


@pytest.mark.asyncio
async def test_server_pack_evidence_contract(monkeypatch):
    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(200, request=request, text="ok")

    async def fake_request(self, method, url, **kwargs):
        request = httpx.Request(method, url)
        return httpx.Response(405, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.pages = []
    result = await run_server_pack(crawl)
    assert result.coverage["evidence_contract"] == "baseline_mutation_result"
    for finding in result.findings:
        assert finding.structured_evidence is not None
        assert finding.structured_evidence.get("baseline_summary")
        assert finding.structured_evidence.get("mutation_summary")
        assert finding.structured_evidence.get("observed_result") is not None


@pytest.mark.asyncio
async def test_api_pack_openapi_diff_and_mass_assign_skipped():
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.endpoints = {
        EndpointCandidate(
            url="http://127.0.0.1/api/known",
            method="GET",
            source="openapi",
        ),
        EndpointCandidate(
            url="http://127.0.0.1/api/secret-undocumented",
            method="GET",
            source="crawl",
        ),
    }
    crawl.normalized_endpoints = [
        NormalizedEndpoint(url="http://127.0.0.1/api/known", method="GET"),
        NormalizedEndpoint(
            url="http://127.0.0.1/api/secret-undocumented",
            method="GET",
        ),
    ]
    result = await run_api_security_pack(crawl, active=False)
    assert any(
        item.check_id == "api.undocumented.public" for item in result.findings
    )
    assert "mass_assignment" in result.skipped
    assert result.coverage["mass_assignment"] == "requires_config"


@pytest.mark.asyncio
async def test_api_auth_inconsistency_finding():
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.auth_comparisons = [
        AuthComparison(
            url="http://127.0.0.1/api/me",
            method="GET",
            boundary="ambiguous",
            anonymous_status=200,
            context_statuses=(("user_a", 200),),
        )
    ]
    result = await run_api_security_pack(crawl, active=False)
    assert any(
        item.check_id == "api.auth.inconsistency" for item in result.findings
    )


def test_graphql_depth_cap_never_huge():
    query = build_depth_query(depth=99, aliases=99)
    assert query.count("a0:") == 1
    assert "a5:" not in query
    assert len(query) < 500


@pytest.mark.asyncio
async def test_graphql_pack_coverage_keys(monkeypatch):
    async def fake_post(self, url, **kwargs):
        request = httpx.Request("POST", url)
        return httpx.Response(
            200,
            request=request,
            json={"data": {"__schema": {"queryType": {"name": "Query"}}}},
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.normalized_endpoints = [
        NormalizedEndpoint(url="http://127.0.0.1/graphql", method="POST"),
    ]
    result = await run_graphql_pack(crawl)
    assert "introspection" in result.coverage["exercised"]
    assert "depth_complexity" in result.coverage["exercised"]
    assert result.coverage["depth_cap"] == 5


@pytest.mark.asyncio
async def test_websocket_cswsh_only_when_accepted():
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.websocket_endpoints = {"ws://127.0.0.1/ws"}

    async def reject_foreign(url, *, origin=None, cookies=None, headers=None):
        accepted = origin is None or "magic-security.invalid" not in (origin or "")
        return WebsocketConnectResult(
            url=url,
            connected=accepted,
            origin=origin,
        )

    rejected = await run_websocket_pack(
        crawl,
        browser=True,
        connect_fn=reject_foreign,
    )
    assert any(
        item.check_id == "websocket.origin.rejected"
        for item in rejected.findings
    )
    assert not any(
        item.check_id == "websocket.cswsh.accepted"
        for item in rejected.findings
    )

    async def accept_foreign(url, *, origin=None, cookies=None, headers=None):
        return WebsocketConnectResult(
            url=url,
            connected=True,
            origin=origin,
        )

    accepted = await run_websocket_pack(
        crawl,
        browser=True,
        connect_fn=accept_foreign,
    )
    assert any(
        item.check_id == "websocket.cswsh.accepted" for item in accepted.findings
    )


@pytest.mark.asyncio
async def test_auth_context_v2_duplicate_and_compat(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps(
            {
                "contexts": [
                    {"name": "a", "cookies": {"s": "1"}},
                    {"name": "b", "cookies": {"s": "2"}},
                ]
            }
        ),
        encoding="utf-8",
    )
    contexts = load_auth_contexts(legacy)
    assert contexts[0].login_mechanism is None
    assert contexts[0].disposable is False

    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        cookie = self.cookies.get("s") if hasattr(self, "cookies") else None
        # Both sessions look identical → duplicate identity.
        return httpx.Response(
            200,
            request=request,
            json={"user": "same"},
        )

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    validation = await validate_auth_identities(
        "http://127.0.0.1/",
        contexts,
    )
    assert validation.duplicate_identities is True
    assert len(validation.valid_contexts) < 2


@pytest.mark.asyncio
async def test_auth_security_enumeration_is_exposure(monkeypatch):
    async def fake_post(self, url, **kwargs):
        request = httpx.Request("POST", url)
        data = kwargs.get("json") or {}
        if data.get("username") == "":
            return httpx.Response(
                400,
                request=request,
                json={"error": "empty"},
            )
        return httpx.Response(
            401,
            request=request,
            json={"error": "unknown user magic-security-missing-user"},
        )

    async def fake_get(self, url, **kwargs):
        request = httpx.Request("GET", url)
        return httpx.Response(404, request=request)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.normalized_endpoints = []
    contexts = [
        AuthContext(name="a", cookies={"s": "1"}),
        AuthContext(name="b", cookies={"s": "2"}),
    ]
    result = await run_auth_security_pack(crawl, contexts)
    enum_findings = [
        item
        for item in result.findings
        if item.check_id == "auth.enumeration.signal"
    ]
    assert enum_findings
    assert enum_findings[0].kind is FindingKind.EXPOSURE
    assert not enum_findings[0].verified or enum_findings[0].confidence < 0.95


def test_authz_matrix_expected_deny_observed_allow():
    crawl = CrawlResult(target="http://127.0.0.1/")
    crawl.pairwise_idor_observations = [
        PairwiseIdorObservation(
            endpoint="http://127.0.0.1/api/accounts/{account_id}",
            parameter="account_id",
            parameter_location="path",
            owner_context="user_a",
            requester_context="user_b",
            owner_status=200,
            requester_status=200,
            cross_account_verified=True,
        )
    ]
    result = build_authz_matrix(
        crawl,
        roles={"user_a": "customer", "user_b": "customer"},
    )
    assert result.rows
    assert any(row.verified for row in result.rows)
    assert result.findings
    assert result.findings[0].verified
    assert "user_b" in result.findings[0].description
    assert "user_a" in result.findings[0].description


def test_registry_includes_new_pack_specs():
    registry = build_default_registry()
    ids = {item.spec.check_id for item in registry.list_checks()}
    assert "exposure.external.pack" in ids
    assert "api.mass-assignment.skipped" in ids
    assert "websocket.cswsh.accepted" in ids
    assert "authorization.matrix.deny-allow" in ids


def test_example_auth_contexts_still_load():
    path = Path("examples/auth_contexts.example.json")
    contexts = load_auth_contexts(path)
    assert len(contexts) >= 2
    assert contexts[0].login_mechanism == "cookie"
