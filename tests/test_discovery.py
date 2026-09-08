from magic_security.discovery import (
    extract_js_endpoints,
    extract_source_maps,
    parameter_names,
)


def test_parameter_names_are_unique_and_sorted():
    assert parameter_names("http://localhost/api?q=one&page=2&q=two") == ("page", "q")


def test_js_endpoint_discovery_extracts_methods_and_params():
    javascript = """
    fetch('/api/users?limit=20');
    axios.post('/api/orders', {item: 1});
    $.get('/api/search?q=magic');
    const graph = "/graphql";
    fetch('https://example.com/external');
    """

    endpoints = extract_js_endpoints(javascript, "http://localhost/static/app.js")
    compact = {(item.method, item.url, item.parameters) for item in endpoints}

    assert ("GET", "http://localhost/api/users?limit=20", ("limit",)) in compact
    assert ("POST", "http://localhost/api/orders", ()) in compact
    assert ("GET", "http://localhost/api/search?q=magic", ("q",)) in compact
    assert ("GET", "http://localhost/graphql", ()) in compact
    assert all("example.com" not in item.url for item in endpoints)


def test_source_map_discovery_resolves_relative_url():
    maps = extract_source_maps(
        "console.log('x');\n//# sourceMappingURL=app.js.map",
        "http://localhost/static/app.js",
    )
    assert maps == {"http://localhost/static/app.js.map"}
