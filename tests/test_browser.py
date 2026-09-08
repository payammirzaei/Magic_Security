from magic_security.browser import merge_rendered_surface, request_parameters
from magic_security.models import CrawlResult


def test_request_parameters_extracts_json_body_and_query():
    params = request_parameters(
        "http://localhost/api/orders?preview=true",
        '{"item": 42, "coupon": "demo"}',
        "application/json",
    )
    assert params == ("coupon", "item", "preview")


def test_request_parameters_extracts_form_body():
    params = request_parameters(
        "http://localhost/login",
        "email=a%40b.test&password=demo",
        "application/x-www-form-urlencoded",
    )
    assert params == ("email", "password")


def test_merge_rendered_surface_adds_dynamic_links_forms_and_scripts():
    crawl = CrawlResult(target="http://localhost:3000")

    merge_rendered_surface(
        crawl,
        page_url="http://localhost:3000/dashboard",
        links=[
            "http://localhost:3000/orders?id=7",
            "https://example.com/external",
        ],
        scripts=[
            "http://localhost:3000/_next/app.js",
            "https://cdn.example.com/app.js",
        ],
        forms=[
            {
                "action": "http://localhost:3000/profile",
                "method": "POST",
                "parameters": ["name", "email"],
            }
        ],
    )

    assert "http://localhost:3000/orders?id=7" in crawl.links
    assert "https://example.com/external" not in crawl.links
    assert "http://localhost:3000/_next/app.js" in crawl.js_assets
    assert "https://cdn.example.com/app.js" not in crawl.js_assets

    endpoints = {
        (item.url, item.method, item.source, item.parameters)
        for item in crawl.endpoints
    }
    assert (
        "http://localhost:3000/orders?id=7",
        "GET",
        "browser:link",
        ("id",),
    ) in endpoints
    assert (
        "http://localhost:3000/profile",
        "POST",
        "browser:form",
        ("email", "name"),
    ) in endpoints
