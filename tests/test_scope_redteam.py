"""STEP 52 — Scope bypass red-team suite (fail closed)."""

from __future__ import annotations

import pytest

from magic_security.config import ScopeConfig
from magic_security.scope import ScopePolicy, is_loopback_host, is_local_target


@pytest.fixture
def local_policy() -> ScopePolicy:
    return ScopePolicy(
        ScopeConfig(loopback_only=True, same_origin=True, deny_external_redirects=True),
        target="http://127.0.0.1:8000/",
        allow_remote=False,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1.evil.com/",
        "http://127.0.0.1.attacker.test/x",
        "http://localhost.evil.com/",
        "https://example.com/",
        "http://2130706433/",  # decimal 127.0.0.1 — still loopback; see allow list
        "http://0x7f000001/",  # hex loopback — allowed as loopback encoding
        "http://8.8.8.8/",
        "http://[::ffff:8.8.8.8]/",
        "http://user:pass@example.com/",
        "http://127.0.0.1@example.com/",  # host is example.com
        "http://xn--localhost-evil.example/",
        "ftp://127.0.0.1/",
        "file:///etc/passwd",
    ],
)
def test_scope_blocks_or_classifies_bypass_candidates(local_policy: ScopePolicy, url: str):
    host_is_encoded_loopback = any(
        x in url for x in ("2130706433", "0x7f000001", "0177.0.0.01")
    )
    decision = local_policy.decide(url)
    if host_is_encoded_loopback:
        assert decision.allowed
        assert is_loopback_host(
            __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url).hostname
        )
    else:
        assert not decision.allowed, f"should block {url}: {decision}"


def test_decimal_and_hex_loopback_recognized():
    assert is_loopback_host("2130706433")
    assert is_loopback_host("0x7f000001")
    assert is_loopback_host("0177.0.0.01")
    assert not is_loopback_host("0x08080808")  # 8.8.8.8


def test_ipv6_loopback_and_mapped(local_policy: ScopePolicy):
    assert local_policy.allow("http://[::1]:8000/")
    assert not local_policy.allow("http://[::ffff:8.8.8.8]/")
    # Mapped loopback
    assert is_loopback_host("::ffff:127.0.0.1")


def test_trailing_dot_loopback(local_policy: ScopePolicy):
    assert local_policy.allow("http://127.0.0.1.:8000/")
    assert is_local_target("http://localhost.:8000/", resolve_dns=False) or is_loopback_host(
        "localhost."
    )


def test_userinfo_does_not_confuse_host(local_policy: ScopePolicy):
    # Real host is evil.com
    assert not local_policy.allow("http://127.0.0.1@evil.com/")
    # Real host is loopback
    assert local_policy.allow("http://attacker@127.0.0.1:8000/")


def test_url_fragment_ignored(local_policy: ScopePolicy):
    assert local_policy.allow("http://127.0.0.1:8000/path#https://evil.com")


def test_encoded_hostname_blocked(local_policy: ScopePolicy):
    # Percent-encoded dots forming 127.0.0.1.evil.com style after decode is hard;
    # at minimum external encoded host must fail.
    assert not local_policy.allow("http://example%2ecom/")


def test_scheme_change_redirect(local_policy: ScopePolicy):
    https_target = ScopePolicy(
        ScopeConfig(loopback_only=True, same_origin=True, deny_external_redirects=True),
        target="https://127.0.0.1:8000/",
        allow_remote=False,
    )
    # External https redirect blocked
    d = https_target.decide("https://evil.example/", for_redirect=True)
    assert not d.allowed


def test_websocket_external_blocked(local_policy: ScopePolicy):
    assert not local_policy.allow("wss://evil.example/socket")
    assert local_policy.allow("ws://127.0.0.1:8000/socket")


def test_alternate_port_loopback_ok(local_policy: ScopePolicy):
    assert local_policy.allow("http://127.0.0.1:9/")


def test_fail_closed_missing_host(local_policy: ScopePolicy):
    assert not local_policy.allow("http:///nohost")
