from __future__ import annotations

from pathlib import Path

from magic_security.active import run_safe_active_checks
from magic_security.api_security import run_api_security_pack
from magic_security.auth import map_auth_boundaries
from magic_security.auth_context import validate_auth_identities
from magic_security.auth_security import run_auth_security_pack
from magic_security.authz_matrix import build_authz_matrix
from magic_security.behavior_security import classify_rate_limits
from magic_security.browser import BrowserCrawler
from magic_security.browser_pack import run_browser_pack
from magic_security.checks import DEFAULT_CHECKS
from magic_security.classifier import classify_endpoints
from magic_security.config import ScanConfig, scan_config_from_flags
from magic_security.context import ScanContext, create_scan_context
from magic_security.budgets import RequestBudget
from magic_security.coverage_registry import build_coverage_registry
from magic_security.crawler import HttpCrawler
from magic_security.exposure_pack_v2 import run_exposure_pack_v2
from magic_security.external_coverage import build_external_security_coverage
from magic_security.fingerprints import (
    deduplicate_findings,
    group_response_fingerprints,
)
from magic_security.graphql_pack import run_graphql_pack
from magic_security.historical import seed_historical_endpoints
from magic_security.idor import verify_pairwise_idor_read_access
from magic_security.index_discovery import discover_index_documents
from magic_security.js_analysis import analyze_javascript
from magic_security.logging_metrics import StructuredLogger
from magic_security.pack_runner import run_isolated
from magic_security.models import AuthContext, CrawlResult, EndpointCandidate, Finding, Severity
from magic_security.openapi import discover_openapi_endpoints
from magic_security.rate_limit import RateLimiter
from magic_security.redaction import Redactor
from magic_security.registry import CheckStatus, build_default_registry
from magic_security.server_pack import run_server_pack
from magic_security.scope import ScopePolicy, is_local_target
from magic_security.surface import normalize_endpoints
from magic_security.surface_graph import build_attack_surface_graph
from magic_security.user_side_coverage import build_user_side_security_coverage
from magic_security.user_surface_security import verify_jsonp_and_null_origin_cors
from magic_security.websocket_security import run_websocket_pack
from magic_security.workflow_packs import run_workflow_packs
from magic_security.workflow_schema import WorkflowSchemaError


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ScannerEngine:
    def __init__(self, max_pages: int = 100) -> None:
        self.crawler = HttpCrawler(max_pages=max_pages)
        self._default_max_pages = max_pages

    async def scan(
        self,
        target: str | ScanConfig | None = None,
        *,
        config: ScanConfig | None = None,
        active: bool = False,
        browser: bool = False,
        auth_contexts: list[AuthContext] | None = None,
        allow_remote: bool = False,
    ) -> tuple[CrawlResult, list[Finding]]:
        if isinstance(target, ScanConfig):
            config = target
            target = config.target
        elif config is None:
            if target is None:
                raise ValueError("scan() requires a target URL or ScanConfig")
            config = scan_config_from_flags(
                target=target,
                max_pages=self._default_max_pages,
                browser=browser,
                active=active,
                auth_contexts=auth_contexts,
                allow_remote=allow_remote,
            )
        else:
            target = config.target

        active = config.active
        browser = config.browser
        auth_contexts = list(config.auth_contexts) or None
        allow_remote = config.allow_remote

        if self.crawler.max_pages != config.max_pages:
            self.crawler = HttpCrawler(max_pages=config.max_pages)

        if not allow_remote and not is_local_target(target):
            raise ValueError(
                "Remote targets are disabled in the local MVP. "
                "Scan localhost/loopback only."
            )

        if config.active and allow_remote and not is_local_target(target):
            from magic_security.target_registry import (
                TargetRegistry,
                TargetRegistryError,
            )

            try:
                TargetRegistry().assert_active_allowed(
                    target,
                    active=True,
                    allow_remote=True,
                    trusted_local_override=config.trusted_local_override,
                )
            except TargetRegistryError as exc:
                raise ValueError(str(exc)) from exc

        context = create_scan_context(config)
        context.scope = ScopePolicy(
            config.scope,
            target=config.target,
            allow_remote=allow_remote,
        )
        context.budgets = RequestBudget(config.budgets)
        context.metrics.budget_exhausted = False
        context.redactor = Redactor()
        context.logger = StructuredLogger(redactor=context.redactor)
        context.registry = build_default_registry()
        from magic_security.transport import attach_rate_limiter

        attach_rate_limiter(context, config.rate)
        context.logger.scan_start(
            config.target,
            {
                "browser": browser,
                "active": active,
                "auth": bool(auth_contexts),
            },
        )
        from magic_security.transport import bind_scan_context, reset_scan_context

        token = bind_scan_context(context)
        try:
            return await self._scan_body(
                context,
                active=active,
                browser=browser,
                auth_contexts=auth_contexts,
            )
        finally:
            reset_scan_context(token)

    async def _scan_body(
        self,
        context: ScanContext,
        *,
        active: bool,
        browser: bool,
        auth_contexts: list[AuthContext] | None,
    ) -> tuple[CrawlResult, list[Finding]]:
        crawl = await self.crawler.crawl(
            context.target,
            scan_context=context,
        )
        crawl.scan_context = context
        crawl.response_groups = group_response_fingerprints(crawl.pages)

        index_discovery = await discover_index_documents(crawl.target)
        crawl.index_robots_entries = index_discovery.robots_entries
        crawl.index_sitemap_entries = index_discovery.sitemap_entries
        crawl.links.update(index_discovery.links)
        crawl.endpoints.update(index_discovery.endpoints)

        if browser:
            browser_crawler = BrowserCrawler()

            observation = await browser_crawler.enrich(crawl)
            crawl.browser_pages.update(observation.pages_rendered)
            crawl.browser_network_requests += observation.network_requests
            crawl.browser_security_observations.extend(
                observation.security_observations
            )
            crawl.websocket_endpoints.update(observation.websockets)

            if auth_contexts:
                for auth_context in auth_contexts:
                    auth_observation = await browser_crawler.enrich(
                        crawl,
                        auth_context=auth_context,
                    )
                    crawl.authenticated_browser_pages[
                        auth_context.name
                    ] = set(auth_observation.pages_rendered)
                    crawl.authenticated_browser_network_requests[
                        auth_context.name
                    ] = auth_observation.network_requests
                    crawl.browser_security_observations.extend(
                        auth_observation.security_observations
                    )
                    crawl.websocket_endpoints.update(
                        auth_observation.websockets
                    )

        openapi_endpoints = await discover_openapi_endpoints(crawl.target)
        crawl.endpoints.update(openapi_endpoints)
        for endpoint in openapi_endpoints:
            crawl.parameters.update(endpoint.parameters)

        crawl.normalized_endpoints = normalize_endpoints(crawl.endpoints)

        if context.config.baseline_path:
            try:
                from magic_security.backtesting import load_snapshot

                baseline = load_snapshot(context.config.baseline_path)
                (
                    crawl.normalized_endpoints,
                    seeded,
                ) = seed_historical_endpoints(
                    crawl.normalized_endpoints,
                    baseline,
                )
                crawl.historical_endpoints = seeded
                for item in seeded:
                    crawl.endpoints.add(
                        EndpointCandidate(
                            url=item.url,
                            method=item.method,
                            source="historical:snapshot",
                            parameters=item.parameters,
                        )
                    )
                context.logger.discovery_phase(
                    "historical_seed",
                    seeded=len(seeded),
                )
            except Exception as exc:  # noqa: BLE001
                context.logger.check_error(
                    "historical.seed",
                    str(exc),
                )

        findings: list[Finding] = []
        registry = context.registry
        context.logger.pack_start("passive")

        async def _run_passive_pages() -> list[Finding]:
            page_findings: list[Finding] = []
            for page in crawl.pages:
                for check in DEFAULT_CHECKS:
                    page_findings.extend(check.run(page))
            return page_findings

        passive_result = await run_isolated(
            pack="passive",
            check_id="passive.page_checks",
            coro_factory=_run_passive_pages,
            registry=registry,
        )
        findings.extend(passive_result.findings)
        for failure in passive_result.failures:
            crawl.pack_failures.append(
                {
                    "pack": failure.pack,
                    "check_id": failure.check_id,
                    "error_type": failure.error_type,
                    "message": failure.message,
                }
            )
        context.logger.pack_end("passive", findings=len(passive_result.findings))

        exposure = await run_exposure_pack_v2(
            crawl,
            active=active,
            scan_context=context,
        )
        findings.extend(exposure.findings)
        crawl.pack_coverage["exposure_v2"] = exposure.coverage

        # STEP 20: structured JS analysis on discovered assets.
        for asset_url in sorted(crawl.js_assets)[:40]:
            try:
                from magic_security.transport import open_secure_transport

                async with open_secure_transport(
                    context,
                    follow_redirects=True,
                    timeout=5.0,
                ) as client:
                    response = await client.get(asset_url)
                if response.status_code != 200:
                    continue
                analysis = analyze_javascript(response.text[:500_000], asset_url)
                crawl.js_analysis.append(
                    {"url": asset_url, **analysis.to_dict()}
                )
                crawl.endpoints.update(analysis.endpoints)
                crawl.source_maps.update(analysis.source_maps)
                crawl.websocket_endpoints.update(analysis.websocket_urls)
            except Exception:
                continue
        if crawl.js_analysis:
            crawl.normalized_endpoints = normalize_endpoints(crawl.endpoints)

        browser_pack = await run_browser_pack(
            crawl,
            active=active,
            browser=browser,
            auth_contexts=auth_contexts,
        )
        findings.extend(browser_pack.findings)
        crawl.pack_coverage["browser_v2"] = browser_pack.coverage

        if active:
            observations, classification_findings = await classify_endpoints(
                crawl.normalized_endpoints
            )
            crawl.endpoint_observations = observations
            findings.extend(classification_findings)

            findings.extend(
                await run_safe_active_checks(
                    page_urls=(page.url for page in crawl.pages),
                    endpoints=crawl.endpoints,
                )
            )

            (
                active_user_surface,
                active_user_findings,
            ) = await verify_jsonp_and_null_origin_cors(
                crawl.normalized_endpoints
            )
            crawl.user_surface_observations.extend(active_user_surface)
            findings.extend(active_user_findings)

            graphql_pack = await run_graphql_pack(
                crawl,
                auth_contexts=auth_contexts,
            )
            findings.extend(graphql_pack.findings)
            crawl.pack_coverage["graphql_v2"] = graphql_pack.coverage

            crawl.rate_limit_observations = await classify_rate_limits(
                crawl.normalized_endpoints
            )

            server_pack = await run_server_pack(crawl)
            findings.extend(server_pack.findings)
            crawl.pack_coverage["server_v2"] = server_pack.coverage

            api_pack = await run_api_security_pack(
                crawl,
                active=True,
                auth_contexts=auth_contexts,
                auth_comparisons=crawl.auth_comparisons,
            )
            findings.extend(api_pack.findings)
            crawl.pack_coverage["api_v1"] = api_pack.coverage

        ws_pack = await run_websocket_pack(
            crawl,
            browser=browser,
            auth_contexts=auth_contexts,
        )
        findings.extend(ws_pack.findings)
        crawl.pack_coverage["websocket_v1"] = ws_pack.coverage

        if auth_contexts:
            identity = await validate_auth_identities(
                crawl.target,
                auth_contexts,
            )
            crawl.identity_validation = identity.to_dict()
            effective_contexts = identity.valid_contexts
            if identity.duplicate_identities or len(effective_contexts) < 2:
                crawl.pack_coverage["auth_identity"] = {
                    "short_circuited": True,
                    **identity.to_dict(),
                }
                effective_contexts = []
            elif identity.expired_sessions:
                crawl.pack_coverage["auth_identity"] = {
                    "short_circuited_partial": True,
                    **identity.to_dict(),
                }

            if effective_contexts:
                crawl.auth_comparisons = await map_auth_boundaries(
                    crawl.normalized_endpoints,
                    effective_contexts,
                )

                (
                    crawl.ownership_observations,
                    crawl.pairwise_idor_observations,
                    idor_findings,
                ) = await verify_pairwise_idor_read_access(
                    crawl.normalized_endpoints,
                    effective_contexts,
                    auth_comparisons=crawl.auth_comparisons,
                )
                findings.extend(idor_findings)

                auth_pack = await run_auth_security_pack(
                    crawl,
                    effective_contexts,
                )
                findings.extend(auth_pack.findings)
                crawl.pack_coverage["auth_security_v2"] = auth_pack.coverage

                matrix = build_authz_matrix(
                    crawl,
                    roles={
                        item.name: item.role for item in effective_contexts
                    },
                )
                findings.extend(matrix.findings)
                crawl.pack_coverage["authz_matrix_v2"] = matrix.coverage

                run_workflows = bool(
                    context.config.workflows_path
                    or any(item.disposable for item in effective_contexts)
                )
                if run_workflows:
                    try:
                        workflow_result = await run_workflow_packs(
                            crawl,
                            effective_contexts,
                            workflow_path=context.config.workflows_path,
                            browser=browser,
                        )
                        findings.extend(workflow_result.findings)
                        crawl.pack_coverage["workflows_v1"] = (
                            workflow_result.coverage
                        )
                    except WorkflowSchemaError as exc:
                        crawl.pack_failures.append(
                            {
                                "pack": "workflow",
                                "check_id": "workflow.pack",
                                "error_type": "WorkflowSchemaError",
                                "message": str(exc),
                            }
                        )

        crawl.external_security_coverage = build_external_security_coverage(
            crawl.injection_observations,
            crawl.graphql_observations,
            crawl.client_artifact_observations,
            crawl.cors_impact_observations,
            crawl.cache_observations,
            crawl.rate_limit_observations,
            crawl.parameter_security_observations,
            crawl.protocol_security_observations,
        )

        crawl.user_side_security_coverage = (
            build_user_side_security_coverage(
                robots_entries=crawl.index_robots_entries,
                sitemap_entries=crawl.index_sitemap_entries,
                sensitive_endpoints=crawl.sensitive_endpoint_observations,
                user_surface=crawl.user_surface_observations,
            )
        )

        crawl.coverage_registry = build_coverage_registry(
            crawl,
            active=active,
            browser=browser,
            auth_enabled=bool(auth_contexts),
        )

        if context.budgets is not None:
            crawl.budget_coverage = context.budgets.coverage_degradation()
            if context.budgets.exhausted:
                context.metrics.budget_exhausted = True
                context.metrics.note(
                    "budget_exhausted:"
                    + ",".join(context.budgets.exhausted_reasons)
                )
                crawl.coverage_registry.append(
                    {
                        "category": "Scan Budgets",
                        "status": "Partial",
                        "note": (
                            "Request budget exhausted; coverage is incomplete. "
                            f"Reasons: {', '.join(context.budgets.exhausted_reasons)}"
                        ),
                    }
                )
                context.logger.coverage_degradation(
                    list(context.budgets.exhausted_reasons)
                )

        crawl.attack_surface_graph = build_attack_surface_graph(crawl).to_dict()

        if context.config.repo_path:
            from magic_security.repo_security import analyze_repo_security

            repo_result = analyze_repo_security(
                Path(context.config.repo_path),
                crawl=crawl,
            )
            crawl.pack_coverage["repository_security"] = repo_result.coverage
            crawl.repo_findings = repo_result.findings
            crawl.repo_snapshot = repo_result.snapshot
            crawl.repo_correlations = repo_result.correlations

        if registry is not None:
            registry.resolve_for_profile(
                active=active,
                browser=browser,
                auth_enabled=bool(auth_contexts),
                workflow_enabled=bool(
                    context.config.workflows_path
                    or any(
                        getattr(item, "disposable", False)
                        for item in (auth_contexts or [])
                    )
                ),
            )
            crawl.check_coverage = registry.coverage_rows()
        context.logger.metrics.pages = len(crawl.pages)
        context.logger.metrics.endpoints = len(crawl.normalized_endpoints)
        context.logger.metrics.checks_executed = sum(
            1
            for row in crawl.check_coverage
            if row.get("status") == CheckStatus.EXECUTED.value
        )
        for finding in findings:
            context.logger.finding_emitted(
                finding.check_id,
                finding.title,
                finding.verified,
            )
        crawl.scan_metrics = context.logger.metrics.to_dict()
        context.logger.scan_end(
            findings=len(findings),
            duration_ms=0.0,
        )

        findings = deduplicate_findings(findings)
        findings.sort(
            key=lambda f: (
                _SEVERITY_ORDER[f.severity],
                f.title,
                f.url,
            )
        )
        return crawl, findings
