from magic_security.browser import browser_source, merge_rendered_surface
from magic_security.models import AuthContext, CrawlResult


def test_browser_source_includes_auth_context_name_only():
    context = AuthContext(
        name="user_a",
        headers={"Authorization": "Bearer super-secret"},
        cookies={"session": "cookie-secret"},
    )

    source = browser_source("network", context)

    assert source == "browser:user_a:network"
    assert "super-secret" not in source
    assert "cookie-secret" not in source


def test_authenticated_rendered_surface_keeps_context_provenance():
    crawl = CrawlResult(target="http://localhost:3000")
    context = AuthContext(
        name="user_b",
        headers={"X-Test-User": "B"},
    )

    merge_rendered_surface(
        crawl,
        page_url="http://localhost:3000/dashboard",
        links=["http://localhost:3000/account?id=9"],
        scripts=[],
        forms=[
            {
                "action": "http://localhost:3000/profile",
                "method": "POST",
                "parameters": ["display_name"],
            }
        ],
        auth_context=context,
    )

    sources = {item.source for item in crawl.endpoints}
    assert "browser:user_b:link" in sources
    assert "browser:user_b:form" in sources
    assert "B" not in " ".join(sources)
