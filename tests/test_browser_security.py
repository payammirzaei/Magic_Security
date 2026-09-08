from magic_security.browser_security import (
    _analyze_text,
    build_browser_security_coverage,
    storage_observations_from_keys,
)


def test_static_browser_security_finds_dom_message_redirect_and_websocket():
    text = """
    const input = location.hash;
    target.innerHTML = input;

    window.addEventListener("message", (event) => {
        target.innerHTML = event.data;
    });

    function redirectCandidate() {
        const next = location.search;
        if (false) location.href = next;
    }

    if (false) new WebSocket("ws://localhost:8000/ws");
    """

    observations, websockets = _analyze_text(
        "http://localhost/static/app.js",
        text,
        "frontend JavaScript",
    )

    categories = {item.category for item in observations}
    assert "dom_xss" in categories
    assert "web_messaging" in categories
    assert "client_redirect" in categories
    assert "websocket" in categories
    assert "ws://localhost:8000/ws" in websockets

    message = next(
        item
        for item in observations
        if item.category == "web_messaging"
    )
    assert message.status == "missing_origin_check_signal"


def test_storage_keys_are_reported_without_values():
    observations = storage_observations_from_keys(
        page_url="http://localhost/dashboard",
        context_name="user_a",
        local_keys=["access_token", "theme"],
        session_keys=["cart"],
    )

    assert len(observations) == 1
    item = observations[0]
    assert item.category == "browser_storage"
    assert "access_token" in item.evidence
    assert "fake-browser-token" not in item.evidence


def test_browser_security_coverage_counts_signals():
    observations, websockets = _analyze_text(
        "http://localhost/app.js",
        """
        const value = location.hash;
        node.innerHTML = value;
        window.addEventListener("message", event => console.log(event.data));
        if (false) new WebSocket("ws://localhost:8000/ws");
        """,
        "frontend JavaScript",
    )
    observations.extend(
        storage_observations_from_keys(
            page_url="http://localhost/",
            context_name="anonymous",
            local_keys=["jwt_token"],
            session_keys=[],
        )
    )

    coverage = build_browser_security_coverage(
        observations,
        websockets,
        artifacts_scanned=1,
    )

    assert coverage.artifacts_scanned == 1
    assert coverage.dom_source_sink_candidates == 1
    assert coverage.message_handlers == 1
    assert coverage.message_handlers_missing_origin == 1
    assert coverage.sensitive_storage_keys == 1
    assert coverage.websocket_endpoints == 1
