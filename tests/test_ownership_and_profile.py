"""STEP 64/65 — ownership verification + production-safe profile."""

from __future__ import annotations

import pytest

from magic_security.history import HistoryStore
from magic_security.profiles import production_safe_remote_profile
from magic_security.target_registry import (
    AuthorizationState,
    TargetRegistry,
    TargetRegistryError,
    VerificationMethod,
)


def test_well_known_and_dns_verification(tmp_path):
    store = HistoryStore(root=tmp_path / ".magic-security")
    registry = TargetRegistry(store)
    item = registry.register("https://app.example.com", trusted_local=False)
    assert item.authorization_state is AuthorizationState.UNVERIFIED
    item = registry.issue_challenge("https://app.example.com")
    token = item.challenge_token
    assert token

    verified = registry.verify_well_known(
        "https://app.example.com",
        fetch_text=f"ok\n{token}\n",
    )
    assert verified.authorization_state is AuthorizationState.VERIFIED
    assert verified.verification_method is VerificationMethod.WELL_KNOWN

    registry2 = TargetRegistry(HistoryStore(root=tmp_path / ".magic-security-2"))
    registry2.register("https://b.example.com", trusted_local=False)
    registry2.issue_challenge("https://b.example.com")
    item2 = registry2.get("https://b.example.com")
    verified2 = registry2.verify_dns_txt(
        "https://b.example.com",
        txt_records=[f"magic-security-verification={item2.target_id}"],
    )
    assert verified2.verification_method is VerificationMethod.DNS_TXT


def test_suspended_blocks_active(tmp_path):
    store = HistoryStore(root=tmp_path / ".magic-security")
    registry = TargetRegistry(store)
    registry.register("https://app.example.com", trusted_local=False)
    registry.mark_verified(
        "https://app.example.com",
        method=VerificationMethod.TRUSTED_LOCAL,
    )
    registry.suspend("https://app.example.com")
    with pytest.raises(TargetRegistryError):
        registry.assert_active_allowed(
            "https://app.example.com",
            active=True,
            allow_remote=True,
        )


def test_production_safe_profile_denies_dangerous_paths():
    config = production_safe_remote_profile(
        "https://app.example.com",
        allowed_hosts=("app.example.com",),
    )
    for path in ("/payment", "/checkout", "/delete", "/admin"):
        assert path in config.scope.denied_paths or any(
            path.startswith(d) or d.startswith(path)
            for d in config.scope.denied_paths
        )
    assert config.budgets.max_active_mutations == 0
    assert config.workflows_path is None
