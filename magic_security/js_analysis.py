"""JavaScript artifact analysis v2 (STEP 20)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from magic_security.discovery import same_origin
from magic_security.models import EndpointCandidate
from magic_security.redaction import Redactor

# Structured-ish extractors (still regex-backed, but grouped by AST-like roles).
_STRING_LITERAL_RE = re.compile(
    r"""(?P<quote>['"`])(?P<value>(?:\\.|(?!(?P=quote)).)*?)(?P=quote)"""
)
_API_PATH_RE = re.compile(
    r"^/(?:api|graphql|rest|v\d+)(?:/[A-Za-z0-9_\-{}]*)*$",
    re.IGNORECASE,
)
_ROUTE_PATH_RE = re.compile(
    r"^/(?:app|dashboard|settings|admin|login|account)(?:/[A-Za-z0-9_\-{}]*)*$",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"^(?:ws|wss)://", re.IGNORECASE)
_SOURCE_MAP_RE = re.compile(
    r"""(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*(?P<url>[^\s*]+)""",
    re.IGNORECASE,
)
_POSTMESSAGE_RE = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]""",
    re.IGNORECASE,
)
_SINK_RE = re.compile(
    r"\b(?:innerHTML|outerHTML|document\.write|eval|new Function)\b"
)
_SOURCE_RE = re.compile(
    r"\b(?:location\.search|location\.hash|document\.URL|document\.referrer|window\.name)\b"
)
_INTERNAL_URL_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?(?:/[^\s'\"`]*)?",
    re.IGNORECASE,
)
_SECRET_ASSIGN_RE = re.compile(
    r"""(?ix)\b(?P<name>[A-Z0-9_$.-]*(?:secret|password|api[_-]?key|token|private[_-]?key)[A-Z0-9_$.-]*)\s*[:=]\s*(?P<quote>['"`])(?P<value>[^'"`]{6,})(?P=quote)"""
)


@dataclass
class JsAnalysisResult:
    api_paths: list[str] = field(default_factory=list)
    graphql_paths: list[str] = field(default_factory=list)
    websocket_urls: list[str] = field(default_factory=list)
    client_routes: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    dangerous_sinks: list[str] = field(default_factory=list)
    browser_sources: list[str] = field(default_factory=list)
    postmessage_handlers: int = 0
    internal_urls: list[str] = field(default_factory=list)
    secret_like_names: list[str] = field(default_factory=list)
    endpoints: list[EndpointCandidate] = field(default_factory=list)
    confidence: str = "heuristic"

    def to_dict(self) -> dict:
        return {
            "api_paths": self.api_paths,
            "graphql_paths": self.graphql_paths,
            "websocket_urls": self.websocket_urls,
            "client_routes": self.client_routes,
            "source_maps": self.source_maps,
            "dangerous_sinks": self.dangerous_sinks,
            "browser_sources": self.browser_sources,
            "postmessage_handlers": self.postmessage_handlers,
            "internal_urls": self.internal_urls,
            "secret_like_names": self.secret_like_names,
            "endpoint_count": len(self.endpoints),
            "confidence": self.confidence,
        }


def _extract_string_literals(text: str) -> list[str]:
    values: list[str] = []
    for match in _STRING_LITERAL_RE.finditer(text):
        value = match.group("value")
        # Cheap unescape for common cases.
        value = value.replace("\\/", "/").replace("\\n", "").strip()
        if value:
            values.append(value)
    return values


def analyze_javascript(text: str, base_url: str) -> JsAnalysisResult:
    """
    Structured JS analysis with literal extraction first, regex fallback second.
    High-confidence when API/WS/routes come from string literals.
    """
    result = JsAnalysisResult()
    literals = _extract_string_literals(text)
    high_confidence = False

    for literal in literals:
        if _WS_RE.match(literal):
            result.websocket_urls.append(literal)
            high_confidence = True
            continue
        if "graphql" in literal.lower():
            resolved = urljoin(base_url, literal)
            if same_origin(resolved, base_url):
                result.graphql_paths.append(resolved)
                result.endpoints.append(
                    EndpointCandidate(
                        url=resolved,
                        method="POST",
                        source="js_analysis:graphql",
                        parameters=(),
                    )
                )
                high_confidence = True
            continue
        if _API_PATH_RE.match(literal):
            resolved = urljoin(base_url, literal)
            if same_origin(resolved, base_url):
                result.api_paths.append(resolved)
                result.endpoints.append(
                    EndpointCandidate(
                        url=resolved,
                        method="GET",
                        source="js_analysis:api",
                        parameters=(),
                    )
                )
                high_confidence = True
            continue
        if _ROUTE_PATH_RE.match(literal):
            resolved = urljoin(base_url, literal)
            if same_origin(resolved, base_url):
                result.client_routes.append(resolved)
                high_confidence = True

    for match in _SOURCE_MAP_RE.finditer(text):
        result.source_maps.append(urljoin(base_url, match.group("url")))

    result.dangerous_sinks = sorted(set(_SINK_RE.findall(text)))
    result.browser_sources = sorted(set(_SOURCE_RE.findall(text)))
    result.postmessage_handlers = len(_POSTMESSAGE_RE.findall(text))
    result.internal_urls = sorted(set(_INTERNAL_URL_RE.findall(text)))

    redactor = Redactor()
    names: set[str] = set()
    for match in _SECRET_ASSIGN_RE.finditer(text):
        names.add(match.group("name"))
        # Never keep the secret value.
        _ = redactor.redact_scalar(match.group("value"), key=match.group("name"))
    result.secret_like_names = sorted(names)

    # Deduplicate lists
    result.api_paths = sorted(set(result.api_paths))
    result.graphql_paths = sorted(set(result.graphql_paths))
    result.websocket_urls = sorted(set(result.websocket_urls))
    result.client_routes = sorted(set(result.client_routes))
    result.source_maps = sorted(set(result.source_maps))
    result.confidence = "structured" if high_confidence else "heuristic"
    return result
