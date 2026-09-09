from __future__ import annotations

from magic_security.config import ScopeConfig
from magic_security.scope import ScopePolicy, is_local_target, is_loopback_url


def test_loopback_hosts_allowed():
    policy = ScopePolicy(ScopeConfig(), target="http://127.0.0.1:8000")
    assert policy.allow("http://127.0.0.1:8000/api")
    assert policy.allow("http://localhost:8000/")
    assert policy.allow("http://[::1]:8000/")
    assert is_loopback_url("http://127.0.0.1/")
    assert is_local_target("http://127.0.0.1:8000")


def test_external_host_blocked():
    policy = ScopePolicy(ScopeConfig(), target="http://127.0.0.1:8000")
    decision = policy.decide("https://example.com/")
    assert not decision.allowed
    assert "non_loopback" in decision.reason or "cross_origin" in decision.reason


def test_external_redirect_blocked():
    policy = ScopePolicy(
        ScopeConfig(deny_external_redirects=True),
        target="http://127.0.0.1:8000",
    )
    decision = policy.decide(
        "https://evil.example/",
        for_redirect=True,
    )
    assert not decision.allowed


def test_deceptive_hostname_blocked():
    policy = ScopePolicy(ScopeConfig(), target="http://127.0.0.1:8000")
    assert not policy.allow("http://127.0.0.1.attacker.test/")


def test_denied_path_blocked():
    policy = ScopePolicy(
        ScopeConfig(denied_paths=("/admin/delete-all",)),
        target="http://127.0.0.1:8000",
        allow_remote=True,
    )
    # Still loopback-only by default unless allow_remote + loopback_only false
    policy = ScopePolicy(
        ScopeConfig(
            loopback_only=True,
            denied_paths=("/admin/delete-all",),
        ),
        target="http://127.0.0.1:8000",
    )
    decision = policy.decide("http://127.0.0.1:8000/admin/delete-all")
    assert not decision.allowed
    assert decision.reason.startswith("denied_path")
