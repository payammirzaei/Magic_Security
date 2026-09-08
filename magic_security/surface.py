from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from magic_security.models import EndpointCandidate, NormalizedEndpoint


def canonical_endpoint_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def normalize_endpoints(
    endpoints: set[EndpointCandidate],
) -> list[NormalizedEndpoint]:
    grouped: dict[tuple[str, str], dict[str, set[str]]] = {}

    for endpoint in endpoints:
        method = endpoint.method.upper()
        url = canonical_endpoint_url(endpoint.url)
        key = (method, url)
        bucket = grouped.setdefault(
            key,
            {"parameters": set(), "sources": set()},
        )
        bucket["parameters"].update(endpoint.parameters)
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
