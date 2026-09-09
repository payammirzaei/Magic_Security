"""Attack surface graph v1 (STEP 16)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit

from magic_security.models import CrawlResult


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackSurfaceGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> GraphNode:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        existing.data.update(node.data)
        return existing

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [asdict(node) for node in self.nodes.values()],
            "edges": [asdict(edge) for edge in self.edges],
        }

    def endpoints_for_page(self, page_url: str) -> list[str]:
        page_id = f"page:{page_url}"
        targets = [
            edge.target
            for edge in self.edges
            if edge.source == page_id and edge.type in {"calls", "links_to", "discovered_from"}
        ]
        return [
            self.nodes[node_id].label
            for node_id in targets
            if node_id in self.nodes and self.nodes[node_id].type == "endpoint"
        ]

    def parameters_for_endpoint(self, method: str, url: str) -> list[str]:
        endpoint_id = f"endpoint:{method.upper()}:{url}"
        return [
            self.nodes[edge.target].label
            for edge in self.edges
            if edge.source == endpoint_id
            and edge.type == "accepts"
            and edge.target in self.nodes
        ]

    def contexts_for_endpoint(self, method: str, url: str) -> list[str]:
        endpoint_id = f"endpoint:{method.upper()}:{url}"
        return [
            self.nodes[edge.source].label
            for edge in self.edges
            if edge.target == endpoint_id
            and edge.type in {"visible_to", "requires_auth"}
            and edge.source in self.nodes
        ]


def build_attack_surface_graph(crawl: CrawlResult) -> AttackSurfaceGraph:
    graph = AttackSurfaceGraph()
    target_id = f"target:{crawl.target}"
    graph.add_node(GraphNode(target_id, "target", crawl.target))

    for page in crawl.pages:
        page_id = f"page:{page.url}"
        graph.add_node(GraphNode(page_id, "page", page.url))
        graph.add_edge(GraphEdge(target_id, page_id, "links_to"))

    for link in crawl.links:
        link_id = f"page:{link}"
        graph.add_node(GraphNode(link_id, "page", link))

    for asset in crawl.js_assets:
        node_id = f"js:{asset}"
        graph.add_node(GraphNode(node_id, "js_asset", asset))
        graph.add_edge(GraphEdge(target_id, node_id, "loads"))

    for source_map in crawl.source_maps:
        node_id = f"sourcemap:{source_map}"
        graph.add_node(GraphNode(node_id, "source_map", source_map))
        graph.add_edge(GraphEdge(target_id, node_id, "loads"))

    for ws in crawl.websocket_endpoints:
        node_id = f"websocket:{ws}"
        graph.add_node(GraphNode(node_id, "websocket", ws))
        graph.add_edge(GraphEdge(target_id, node_id, "calls"))

    for endpoint in crawl.normalized_endpoints:
        endpoint_id = f"endpoint:{endpoint.method}:{endpoint.url}"
        graph.add_node(
            GraphNode(
                endpoint_id,
                "endpoint",
                f"{endpoint.method} {endpoint.url}",
                {
                    "method": endpoint.method,
                    "url": endpoint.url,
                    "sources": list(endpoint.sources),
                },
            )
        )
        for source in endpoint.sources:
            if source.startswith("html:") or source.startswith("browser:"):
                # Prefer page discovery edges when URL path matches a known page.
                path = urlsplit(endpoint.url).path
                for page in crawl.pages:
                    if urlsplit(page.url).path == path or page.url == endpoint.url:
                        graph.add_edge(
                            GraphEdge(
                                f"page:{page.url}",
                                endpoint_id,
                                "discovered_from",
                                {"source": source},
                            )
                        )
                        break
            graph.add_edge(
                GraphEdge(target_id, endpoint_id, "discovered_from", {"source": source})
            )

        for parameter in endpoint.parameters:
            param_id = f"param:{endpoint.method}:{endpoint.url}:{parameter}"
            graph.add_node(
                GraphNode(
                    param_id,
                    "parameter",
                    parameter,
                    {"endpoint": endpoint.url, "method": endpoint.method},
                )
            )
            graph.add_edge(GraphEdge(endpoint_id, param_id, "accepts"))

    for form in crawl.forms:
        action = form.get("action", "")
        form_id = f"form:{action}:{form.get('method', 'GET')}"
        graph.add_node(
            GraphNode(
                form_id,
                "form",
                action,
                {"method": form.get("method", "GET"), "page": form.get("page")},
            )
        )
        page = form.get("page")
        if page:
            graph.add_edge(GraphEdge(f"page:{page}", form_id, "links_to"))

    for comparison in crawl.auth_comparisons:
        endpoint_id = f"endpoint:{comparison.method}:{comparison.url}"
        if comparison.boundary in {"protected", "auth_required"}:
            for context_name, _status in comparison.context_statuses:
                ctx_id = f"auth:{context_name}"
                graph.add_node(GraphNode(ctx_id, "auth_context", context_name))
                graph.add_edge(
                    GraphEdge(ctx_id, endpoint_id, "requires_auth")
                )
                graph.add_edge(
                    GraphEdge(ctx_id, endpoint_id, "visible_to")
                )

    for ownership in crawl.ownership_observations:
        ctx_id = f"auth:{ownership.context}"
        graph.add_node(GraphNode(ctx_id, "auth_context", ownership.context))
        resource_id = f"resource:{ownership.parameter}"
        graph.add_node(
            GraphNode(
                resource_id,
                "resource_id",
                ownership.parameter,
                {"discovered_values": ownership.discovered_values},
            )
        )
        graph.add_edge(GraphEdge(ctx_id, resource_id, "owns"))

    for cookie in crawl.session_cookie_observations:
        cookie_id = f"cookie:{cookie.context}:{cookie.cookie_name}"
        graph.add_node(
            GraphNode(
                cookie_id,
                "cookie",
                cookie.cookie_name,
                {"context": cookie.context},
            )
        )

    for observation in crawl.browser_security_observations:
        if observation.category == "browser_storage":
            key = observation.evidence.split("'")[1] if "'" in observation.evidence else "storage"
            storage_id = f"storage:{observation.context or 'anonymous'}:{key}"
            graph.add_node(
                GraphNode(
                    storage_id,
                    "storage_key",
                    key,
                    {"url": observation.url, "context": observation.context},
                )
            )

    return graph
