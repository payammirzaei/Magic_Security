from __future__ import annotations

from urllib.parse import urljoin

import httpx

from magic_security.models import EndpointCandidate


_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _parameter_names(operation: dict, path_item: dict) -> tuple[str, ...]:
    names: set[str] = set()

    for source in (path_item.get("parameters", []), operation.get("parameters", [])):
        if not isinstance(source, list):
            continue
        for item in source:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.add(item["name"])

    request_body = operation.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media in content.values():
                if not isinstance(media, dict):
                    continue
                schema = media.get("schema")
                if not isinstance(schema, dict):
                    continue
                properties = schema.get("properties")
                if isinstance(properties, dict):
                    names.update(str(name) for name in properties)

    return tuple(sorted(names))


def parse_openapi_document(data: dict, base_url: str) -> set[EndpointCandidate]:
    endpoints: set[EndpointCandidate] = set()
    paths = data.get("paths")
    if not isinstance(paths, dict):
        return endpoints

    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue

            endpoints.add(
                EndpointCandidate(
                    url=urljoin(base_url.rstrip("/") + "/", raw_path.lstrip("/")),
                    method=method.upper(),
                    source="openapi",
                    parameters=_parameter_names(operation, path_item),
                )
            )

    return endpoints


async def discover_openapi_endpoints(
    target: str,
    *,
    timeout: float = 5.0,
) -> set[EndpointCandidate]:
    endpoints: set[EndpointCandidate] = set()

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        for path in ("/openapi.json", "/swagger.json"):
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": "Magic-Security/0.4 local-security-scanner"
                    },
                )
            except httpx.HTTPError:
                continue

            if response.status_code != 200:
                continue

            try:
                data = response.json()
            except ValueError:
                continue

            if not isinstance(data, dict):
                continue
            if "openapi" not in data and "swagger" not in data:
                continue

            endpoints.update(parse_openapi_document(data, target))

    return endpoints
