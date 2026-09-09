"""Historical attack surface seeding (STEP 18)."""

from __future__ import annotations

from typing import Any

from magic_security.models import EndpointCandidate, NormalizedEndpoint
from magic_security.surface import canonical_endpoint_url


def endpoints_from_snapshot(snapshot: dict[str, Any]) -> list[NormalizedEndpoint]:
    """Extract normalized endpoints from a previous snapshot attack surface."""
    items = snapshot.get("attack_surface", {}).get("items", [])
    endpoints: list[NormalizedEndpoint] = []

    for item in items:
        if not isinstance(item, str) or not item.startswith("endpoint:"):
            continue
        body = item[len("endpoint:") :]
        method, _, rest = body.partition(":")
        if "://" not in rest:
            continue
        url_part, _, param_text = rest.rpartition(":")
        if "://" not in url_part:
            continue
        params = tuple(sorted(p for p in param_text.split(",") if p))
        endpoints.append(
            NormalizedEndpoint(
                url=canonical_endpoint_url(url_part, normalize_ids=False),
                method=method.upper(),
                parameters=params,
                sources=("historical:snapshot",),
            )
        )
    return endpoints


def seed_historical_endpoints(
    current: list[NormalizedEndpoint],
    snapshot: dict[str, Any] | None,
) -> tuple[list[NormalizedEndpoint], list[NormalizedEndpoint]]:
    """
    Merge historical endpoints into the current list.

    Historical endpoints remain marked via sources and are also returned
    separately so callers never treat them as currently verified presence.
    """
    if not snapshot:
        return current, []

    historical = endpoints_from_snapshot(snapshot)
    current_keys = {(item.method, item.url) for item in current}
    seeded: list[NormalizedEndpoint] = []
    merged = list(current)

    for item in historical:
        key = (item.method, item.url)
        if key in current_keys:
            continue
        seeded.append(item)
        merged.append(item)
        current_keys.add(key)

    merged.sort(key=lambda item: (item.url, item.method))
    return merged, seeded


def historical_candidates(
    seeded: list[NormalizedEndpoint],
) -> list[EndpointCandidate]:
    return [
        EndpointCandidate(
            url=item.url,
            method=item.method,
            source="historical:snapshot",
            parameters=item.parameters,
        )
        for item in seeded
    ]
