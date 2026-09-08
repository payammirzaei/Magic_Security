from magic_security.models import EndpointCandidate
from magic_security.surface import canonical_endpoint_url, normalize_endpoints


def test_canonical_endpoint_url_removes_query_and_fragment():
    assert (
        canonical_endpoint_url(
            "http://localhost:3000/api/users?limit=20#section"
        )
        == "http://localhost:3000/api/users"
    )


def test_normalize_endpoints_merges_sources_and_parameters():
    endpoints = {
        EndpointCandidate(
            url="http://localhost:3000/api/users?limit=20",
            method="GET",
            source="javascript:fetch",
            parameters=("limit",),
        ),
        EndpointCandidate(
            url="http://localhost:3000/api/users",
            method="GET",
            source="openapi",
            parameters=("limit", "include"),
        ),
        EndpointCandidate(
            url="http://localhost:3000/api/users?include=orders",
            method="GET",
            source="browser:network",
            parameters=("include",),
        ),
    }

    result = normalize_endpoints(endpoints)

    assert len(result) == 1
    item = result[0]
    assert item.url == "http://localhost:3000/api/users"
    assert item.method == "GET"
    assert item.parameters == ("include", "limit")
    assert item.sources == (
        "browser:network",
        "javascript:fetch",
        "openapi",
    )


def test_normalize_endpoints_keeps_methods_separate():
    endpoints = {
        EndpointCandidate(
            url="http://localhost/api/orders",
            method="GET",
            source="openapi",
        ),
        EndpointCandidate(
            url="http://localhost/api/orders",
            method="POST",
            source="openapi",
        ),
    }

    result = normalize_endpoints(endpoints)
    assert {(item.method, item.url) for item in result} == {
        ("GET", "http://localhost/api/orders"),
        ("POST", "http://localhost/api/orders"),
    }
