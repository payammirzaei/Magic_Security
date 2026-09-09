"""Improved endpoint and parameter normalization (STEP 17)."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from magic_security.models import EndpointCandidate, NormalizedEndpoint

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_HASH_RE = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_NUMERIC_RE = re.compile(r"^\d+$")
_LOCALE_RE = re.compile(r"^[a-z]{2}(?:-[a-z]{2})?$", re.IGNORECASE)
_NEXT_DYNAMIC_RE = re.compile(r"^\[(?:\.\.\.)?[A-Za-z0-9_]+\]$")
_CACHE_BUST_PARAMS = frozenset(
    {
        "_",
        "v",
        "ver",
        "version",
        "cb",
        "cachebust",
        "cache_bust",
        "t",
        "ts",
        "timestamp",
        "_t",
    }
)
_PAGINATION_PARAMS = frozenset(
    {
        "page",
        "p",
        "offset",
        "limit",
        "per_page",
        "pageSize",
        "page_size",
        "cursor",
    }
)


def normalize_path_segment(segment: str) -> str:
    if not segment:
        return segment
    if _UUID_RE.match(segment):
        return "{uuid}"
    if _NUMERIC_RE.match(segment):
        return "{id}"
    if _HEX_HASH_RE.match(segment):
        return "{hash}"
    if _NEXT_DYNAMIC_RE.match(segment):
        return "{param}"
    if _LOCALE_RE.match(segment) and "-" in segment:
        return "{locale}"
    return segment


def canonical_endpoint_url(url: str, *, normalize_ids: bool = True) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    if normalize_ids:
        segments = [normalize_path_segment(item) for item in path.split("/")]
        # Keep leading empty segment for absolute paths.
        path = "/".join(segments) or "/"
        # Collapse locale prefixes like /en/ or /en-us/ after first segment.
        pieces = path.strip("/").split("/") if path.strip("/") else []
        if pieces and _LOCALE_RE.match(pieces[0]):
            pieces[0] = "{locale}"
            path = "/" + "/".join(pieces)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def meaningful_parameters(
    url: str,
    declared: tuple[str, ...] | list[str] | set[str] = (),
) -> tuple[str, ...]:
    names = set(declared)
    parts = urlsplit(url)
    for key, _value in parse_qsl(parts.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in _CACHE_BUST_PARAMS:
            continue
        names.add(key)
    # Pagination params remain as parameter presence but are kept (security-relevant).
    return tuple(sorted(names))


def normalize_endpoints(
    endpoints: set[EndpointCandidate],
    *,
    normalize_ids: bool = True,
) -> list[NormalizedEndpoint]:
    grouped: dict[tuple[str, str], dict[str, set[str]]] = {}

    for endpoint in endpoints:
        method = endpoint.method.upper()
        url = canonical_endpoint_url(
            endpoint.url,
            normalize_ids=normalize_ids,
        )
        key = (method, url)
        bucket = grouped.setdefault(
            key,
            {"parameters": set(), "sources": set()},
        )
        bucket["parameters"].update(
            meaningful_parameters(endpoint.url, endpoint.parameters)
        )
        # Drop pure cache-bust params from the normalized set.
        bucket["parameters"] = {
            name
            for name in bucket["parameters"]
            if name.lower() not in _CACHE_BUST_PARAMS
        }
        bucket["sources"].add(endpoint.source)

    normalized = [
        NormalizedEndpoint(
            url=url,
            method=method,
            parameters=tuple(sorted(data["parameters"])),
            sources=tuple(sorted(data["sources"])),
        )
        for (method, url), data in grouped.items()
    ]
    normalized.sort(key=lambda item: (item.url, item.method))
    return normalized
