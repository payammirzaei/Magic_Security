from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlparse

from magic_security.models import EndpointCandidate


_FETCH_RE = re.compile(
    r"""\bfetch\s*\(\s*['"](?P<url>[^'"]+)['"]""",
    re.IGNORECASE,
)
_AXIOS_RE = re.compile(
    r"""\baxios\.(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*['"](?P<url>[^'"]+)['"]""",
    re.IGNORECASE,
)
_JQUERY_RE = re.compile(
    r"""\$\.(?P<method>get|post)\s*\(\s*['"](?P<url>[^'"]+)['"]""",
    re.IGNORECASE,
)
_GENERIC_API_PATH_RE = re.compile(
    r"""['"](?P<url>/(?:api|graphql|rest|v\d+)(?:[/\?][^'"\s]*)?)['"]""",
    re.IGNORECASE,
)
_SOURCE_MAP_RE = re.compile(
    r"""(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*(?P<url>[^\s*]+)""",
    re.IGNORECASE,
)


def same_origin(candidate: str, origin: str) -> bool:
    a = urlparse(candidate)
    b = urlparse(origin)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def parameter_names(url: str) -> tuple[str, ...]:
    return tuple(sorted({key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}))


def _resolve_candidate(raw: str, base_url: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith(("data:", "javascript:", "mailto:", "#")):
        return None

    resolved = urljoin(base_url, raw)
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"}:
        return None
    return resolved


def extract_js_endpoints(text: str, base_url: str) -> set[EndpointCandidate]:
    endpoints: set[EndpointCandidate] = set()
    seen_methods: set[tuple[str, str]] = set()
    explicitly_discovered_urls: set[str] = set()

    def add(raw: str, method: str, source: str, *, generic: bool = False) -> None:
        resolved = _resolve_candidate(raw, base_url)
        if not resolved or not same_origin(resolved, base_url):
            return
        if generic and resolved in explicitly_discovered_urls:
            return

        method = method.upper()
        key = (resolved, method)
        if key in seen_methods:
            return

        seen_methods.add(key)
        if not generic:
            explicitly_discovered_urls.add(resolved)

        endpoints.add(
            EndpointCandidate(
                url=resolved,
                method=method,
                source=source,
                parameters=parameter_names(resolved),
            )
        )

    for match in _FETCH_RE.finditer(text):
        add(match.group("url"), "GET", "javascript:fetch")

    for match in _AXIOS_RE.finditer(text):
        add(match.group("url"), match.group("method"), "javascript:axios")

    for match in _JQUERY_RE.finditer(text):
        add(match.group("url"), match.group("method"), "javascript:jquery")

    for match in _GENERIC_API_PATH_RE.finditer(text):
        add(match.group("url"), "GET", "javascript:string", generic=True)

    return endpoints


def extract_source_maps(text: str, asset_url: str) -> set[str]:
    maps: set[str] = set()
    for match in _SOURCE_MAP_RE.finditer(text):
        resolved = _resolve_candidate(match.group("url").rstrip("*/"), asset_url)
        if resolved and same_origin(resolved, asset_url):
            maps.add(resolved)
    return maps
