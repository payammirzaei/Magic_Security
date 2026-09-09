"""Central scope enforcement (STEP 6)."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from magic_security.config import ScopeConfig


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: str


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_loopback_url(url: str) -> bool:
    return is_loopback_host(urlparse(url).hostname)


def is_local_target(target: str, *, resolve_dns: bool = True) -> bool:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname
    if not host:
        return False
    if is_loopback_host(host):
        return True
    if not resolve_dns:
        return False

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return False

    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_loopback:
                return False
        except ValueError:
            return False
    return bool(addresses)


def same_origin(candidate: str, origin: str) -> bool:
    a = urlparse(candidate)
    b = urlparse(origin)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


class ScopePolicy:
    def __init__(
        self,
        config: ScopeConfig | None = None,
        *,
        target: str | None = None,
        allow_remote: bool = False,
    ) -> None:
        self.config = config or ScopeConfig()
        self.target = target
        self.allow_remote = allow_remote

    def decide(self, url: str, *, for_redirect: bool = False) -> ScopeDecision:
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in {"http", "https", "ws", "wss"}:
            return ScopeDecision(False, f"scheme_not_allowed:{parsed.scheme}")

        host = parsed.hostname
        if host is None:
            return ScopeDecision(False, "missing_host")

        # Deceptive hostnames that look local but are not.
        lowered = host.lower()
        if lowered.endswith(".localhost.evil") or "127.0.0.1." in lowered:
            return ScopeDecision(False, "deceptive_hostname")

        path = parsed.path or "/"
        for denied in self.config.denied_paths:
            if path == denied or path.startswith(denied.rstrip("/") + "/"):
                return ScopeDecision(False, f"denied_path:{denied}")

        if self.config.allowed_hosts and lowered not in {
            item.lower() for item in self.config.allowed_hosts
        }:
            if not (
                self.config.loopback_only
                and not self.allow_remote
                and is_local_target(url)
            ):
                return ScopeDecision(False, "host_not_allowlisted")

        if self.config.loopback_only and not self.allow_remote:
            if not is_local_target(url):
                return ScopeDecision(False, "non_loopback_blocked")

        if (
            for_redirect
            and self.config.deny_external_redirects
            and self.target
            and not same_origin(url, self.target)
        ):
            # Same-origin relative redirects are fine; cross-origin blocked.
            if not (self.allow_remote and not self.config.loopback_only):
                if self.config.loopback_only and not is_loopback_url(url):
                    return ScopeDecision(False, "external_redirect_blocked")
                if self.config.same_origin and not same_origin(url, self.target):
                    return ScopeDecision(False, "cross_origin_redirect_blocked")

        if (
            self.config.same_origin
            and self.target
            and not for_redirect
            and parsed.scheme in {"http", "https"}
            and not same_origin(url, self.target)
            and not is_loopback_url(url)
        ):
            return ScopeDecision(False, "cross_origin_blocked")

        return ScopeDecision(True, "allowed")

    def allow(self, url: str, *, for_redirect: bool = False) -> bool:
        return self.decide(url, for_redirect=for_redirect).allowed
