"""Remote authorized target registry (STEP 43)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from magic_security.history import HistoryStore, target_id_for
from magic_security.scope import is_local_target


class AuthorizationState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"


class VerificationMethod(str, Enum):
    DNS_TXT = "dns_txt"
    WELL_KNOWN = "well_known"
    TRUSTED_LOCAL = "trusted_local"
    REPO_LINK = "repository_linkage"


@dataclass
class RegisteredTarget:
    target_id: str
    base_url: str
    environment: str = "staging"
    allowed_hosts: list[str] = field(default_factory=list)
    denied_paths: list[str] = field(default_factory=list)
    authorization_state: AuthorizationState = AuthorizationState.UNVERIFIED
    verification_method: VerificationMethod | None = None
    production_safe_limits: dict[str, Any] = field(default_factory=dict)
    challenge_token: str | None = None
    verified_at: str | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["authorization_state"] = self.authorization_state.value
        data["verification_method"] = (
            self.verification_method.value if self.verification_method else None
        )
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RegisteredTarget:
        return cls(
            target_id=str(data["target_id"]),
            base_url=str(data["base_url"]),
            environment=str(data.get("environment") or "staging"),
            allowed_hosts=list(data.get("allowed_hosts") or []),
            denied_paths=list(data.get("denied_paths") or []),
            authorization_state=AuthorizationState(
                data.get("authorization_state") or "UNVERIFIED"
            ),
            verification_method=(
                VerificationMethod(data["verification_method"])
                if data.get("verification_method")
                else None
            ),
            production_safe_limits=dict(
                data.get("production_safe_limits") or {}
            ),
            challenge_token=data.get("challenge_token"),
            verified_at=data.get("verified_at"),
            notes=str(data.get("notes") or ""),
        )


class TargetRegistryError(ValueError):
    pass


class TargetRegistry:
    def __init__(self, store: HistoryStore | None = None) -> None:
        self.store = store or HistoryStore()

    def _meta_path(self, target: str) -> Path:
        return self.store.target_dir(target) / "registry.json"

    def register(
        self,
        base_url: str,
        *,
        environment: str = "staging",
        allowed_hosts: list[str] | None = None,
        denied_paths: list[str] | None = None,
        trusted_local: bool = False,
    ) -> RegisteredTarget:
        host = urlparse(base_url).hostname
        if not host:
            raise TargetRegistryError("base_url needs a host")
        hosts = allowed_hosts or [host]
        item = RegisteredTarget(
            target_id=target_id_for(base_url),
            base_url=base_url,
            environment=environment,
            allowed_hosts=hosts,
            denied_paths=list(denied_paths or []),
            production_safe_limits={
                "max_total_requests": 500,
                "max_active_mutations": 0,
                "requests_per_second": 1.0,
            },
        )
        if trusted_local or is_local_target(base_url):
            item.authorization_state = AuthorizationState.VERIFIED
            item.verification_method = VerificationMethod.TRUSTED_LOCAL
            item.verified_at = datetime.now(timezone.utc).isoformat()
        else:
            item.challenge_token = f"magic-security-verify-{item.target_id}"
        self.store.add_target(base_url)
        self._meta_path(base_url).write_text(
            json.dumps(item.to_dict(), indent=2),
            encoding="utf-8",
        )
        return item

    def get(self, base_url: str) -> RegisteredTarget | None:
        path = self._meta_path(base_url)
        if not path.exists():
            return None
        return RegisteredTarget.from_dict(
            json.loads(path.read_text(encoding="utf-8"))
        )

    def mark_verified(
        self,
        base_url: str,
        *,
        method: VerificationMethod,
    ) -> RegisteredTarget:
        item = self.get(base_url)
        if item is None:
            raise TargetRegistryError(f"Unknown target: {base_url}")
        item.authorization_state = AuthorizationState.VERIFIED
        item.verification_method = method
        item.verified_at = datetime.now(timezone.utc).isoformat()
        self._meta_path(base_url).write_text(
            json.dumps(item.to_dict(), indent=2),
            encoding="utf-8",
        )
        return item

    def assert_active_allowed(
        self,
        base_url: str,
        *,
        active: bool,
        allow_remote: bool,
        trusted_local_override: bool = False,
    ) -> None:
        if not active:
            return
        if is_local_target(base_url) or trusted_local_override:
            return
        if not allow_remote:
            raise TargetRegistryError(
                "Remote active scans require allow_remote and a verified target"
            )
        item = self.get(base_url)
        if item is None:
            raise TargetRegistryError(
                "Unverified remote target cannot run active packs"
            )
        if item.authorization_state is AuthorizationState.UNVERIFIED:
            raise TargetRegistryError(
                "Unverified remote target cannot run active packs"
            )
        if item.authorization_state is AuthorizationState.SUSPENDED:
            raise TargetRegistryError(
                "Target authorization state is SUSPENDED"
            )
        if item.authorization_state is AuthorizationState.EXPIRED:
            raise TargetRegistryError(
                "Target authorization state is EXPIRED"
            )
        if item.authorization_state is not AuthorizationState.VERIFIED:
            raise TargetRegistryError(
                "Unverified remote target cannot run active packs"
            )

    def issue_challenge(self, base_url: str) -> RegisteredTarget:
        item = self.get(base_url)
        if item is None:
            item = self.register(base_url, trusted_local=False)
        if not item.challenge_token:
            item.challenge_token = f"magic-security-verification={item.target_id}"
            self._meta_path(base_url).write_text(
                json.dumps(item.to_dict(), indent=2),
                encoding="utf-8",
            )
        return item

    def verify_well_known(
        self,
        base_url: str,
        *,
        fetch_text: str | None = None,
    ) -> RegisteredTarget:
        """Verify /.well-known/magic-security-verification.txt contents."""
        item = self.issue_challenge(base_url)
        expected = item.challenge_token or ""
        body = fetch_text
        if body is None:
            from magic_security.transport import open_secure_transport
            import asyncio

            async def _fetch() -> str:
                url = base_url.rstrip("/") + "/.well-known/magic-security-verification.txt"
                async with open_secure_transport(timeout=5.0) as client:
                    response = await client.get(url)
                    return response.text

            try:
                body = asyncio.get_event_loop().run_until_complete(_fetch())
            except Exception as exc:  # noqa: BLE001
                raise TargetRegistryError(f"well-known fetch failed: {exc}") from exc
        if expected not in (body or ""):
            raise TargetRegistryError("well-known challenge mismatch")
        return self.mark_verified(base_url, method=VerificationMethod.WELL_KNOWN)

    def verify_dns_txt(
        self,
        base_url: str,
        *,
        txt_records: list[str] | None = None,
    ) -> RegisteredTarget:
        """Verify DNS TXT at _magic-security.<host>."""
        item = self.issue_challenge(base_url)
        host = urlparse(base_url).hostname
        if not host:
            raise TargetRegistryError("invalid host")
        expected = item.challenge_token or ""
        records = txt_records
        if records is None:
            import socket

            name = f"_magic-security.{host}"
            try:
                # Prefer dnspython-free: getaddrinfo won't return TXT; require injection in tests
                # or optional DNS lookup via socket.getaddrinfo is insufficient.
                raise TargetRegistryError(
                    f"Pass txt_records= for verification of {name} "
                    "(live DNS TXT lookup requires operator-supplied records in this build)"
                )
            except socket.gaierror as exc:
                raise TargetRegistryError(str(exc)) from exc
        joined = " ".join(records)
        if expected not in joined and f"magic-security-verification={item.target_id}" not in joined:
            if expected.split("=", 1)[-1] not in joined and item.target_id not in joined:
                raise TargetRegistryError("dns txt challenge mismatch")
        return self.mark_verified(base_url, method=VerificationMethod.DNS_TXT)

    def suspend(self, base_url: str) -> RegisteredTarget:
        item = self.get(base_url)
        if item is None:
            raise TargetRegistryError(f"Unknown target: {base_url}")
        item.authorization_state = AuthorizationState.SUSPENDED
        self._meta_path(base_url).write_text(
            json.dumps(item.to_dict(), indent=2),
            encoding="utf-8",
        )
        return item

    def expire(self, base_url: str) -> RegisteredTarget:
        item = self.get(base_url)
        if item is None:
            raise TargetRegistryError(f"Unknown target: {base_url}")
        item.authorization_state = AuthorizationState.EXPIRED
        self._meta_path(base_url).write_text(
            json.dumps(item.to_dict(), indent=2),
            encoding="utf-8",
        )
        return item
