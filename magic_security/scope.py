"""Central scope enforcement (STEP 6 / STEP 52 hardening)."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

from magic_security.config import ScopeConfig


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: str


_DECIMAL_HOST = re.compile(r"^\d{8,10}$")
_HEX_HOST = re.compile(r"^0x[0-9a-fA-F]+$", re.IGNORECASE)
_OCTAL_HOST = re.compile(
    r"^(0[0-7]{0,3}|[0-7]{1,3})(\.(0[0-7]{0,3}|[0-7]{1,3})){3}$"
)


def _normalize_hostname(host: str | None) -> str | None:
    if not host:
        return None
    # Strip trailing dots (DNS absolute name form).
    cleaned = host.strip().rstrip(".").lower()
    # Decode percent-encoding once (e.g. %31%32%37...).
    try:
        cleaned = unquote(cleaned)
    except Exception:
        pass
    return cleaned or None


def _parse_weird_ip(host: str) -> ipaddress._BaseAddress | None:
    """Reject / classify decimal, hex, octal, and mapped IP forms."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Decimal IPv4 (e.g. 2130706433 == 127.0.0.1)
    if _DECIMAL_HOST.match(host):
        try:
            value = int(host)
            if 0 <= value <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(value)
        except ValueError:
            return None
    # Hex IPv4 (e.g. 0x7f000001)
    if _HEX_HOST.match(host):
        try:
            return ipaddress.IPv4Address(int(host, 16))
        except ValueError:
            return None
    # Octal-dotted IPv4 (e.g. 0177.0.0.01)
    if _OCTAL_HOST.match(host) and host.count(".") == 3:
        try:
            parts = [int(p, 8) for p in host.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return ipaddress.IPv4Address(".".join(str(p) for p in parts))
        except ValueError:
            return None
    return None


def is_loopback_host(host: str | None) -> bool:
    host = _normalize_hostname(host)
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    parsed = _parse_weird_ip(host)
    if parsed is not None:
        # IPv4-mapped IPv6 (::ffff:127.0.0.1) — treat mapped address.
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return parsed.ipv4_mapped.is_loopback
        return parsed.is_loopback
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_loopback_url(url: str) -> bool:
    return is_loopback_host(urlparse(url).hostname)


def is_local_target(target: str, *, resolve_dns: bool = True) -> bool:
    parsed = urlparse(target if "://" in target else f"http://{target}")
    host = _normalize_hostname(parsed.hostname)
    if not host:
        return False
    # Userinfo tricks: treat presence of @ in netloc carefully — urlparse already
    # separates username; hostname should be the real host.
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
    a_host = _normalize_hostname(a.hostname)
    b_host = _normalize_hostname(b.hostname)
    a_port = a.port or (443 if a.scheme == "https" else 80)
    b_port = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme, a_host, a_port) == (b.scheme, b_host, b_port)


def _deceptive_hostname(host: str) -> bool:
    lowered = host.lower()
    if lowered.endswith(".localhost.evil") or "127.0.0.1." in lowered:
        return True
    if "localhost." in lowered and not lowered.endswith(".localhost"):
        # e.g. localhost.evil.com
        if not lowered.endswith(".localhost") and lowered != "localhost":
            labels = lowered.split(".")
            if "localhost" in labels[:-1] or labels[0] == "127":
                return True
    # Punycode / IDN that embeds local-looking labels
    if "xn--" in lowered and ("localhost" in lowered or "127" in lowered):
        return True
    return False


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
        # Fragments must not affect scope — urlparse strips them from path host.
        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in {"http", "https", "ws", "wss"}:
            return ScopeDecision(False, f"scheme_not_allowed:{parsed.scheme}")

        host = _normalize_hostname(parsed.hostname)
        if host is None:
            return ScopeDecision(False, "missing_host")

        if _deceptive_hostname(host):
            return ScopeDecision(False, "deceptive_hostname")

        # Weird IP encodings that resolve to non-loopback while looking local.
        weird = _parse_weird_ip(host)
        if weird is not None:
            mapped = (
                weird.ipv4_mapped
                if isinstance(weird, ipaddress.IPv6Address)
                else None
            )
            effective = mapped or weird
            if self.config.loopback_only and not self.allow_remote:
                if not effective.is_loopback:
                    return ScopeDecision(False, "non_loopback_encoded_ip")

        path = parsed.path or "/"
        for denied in self.config.denied_paths:
            if path == denied or path.startswith(denied.rstrip("/") + "/"):
                return ScopeDecision(False, f"denied_path:{denied}")

        if self.config.allowed_hosts and host not in {
            item.lower().rstrip(".") for item in self.config.allowed_hosts
        }:
            if not (
                self.config.loopback_only
                and not self.allow_remote
                and is_local_target(url, resolve_dns=False)
            ):
                return ScopeDecision(False, "host_not_allowlisted")

        if self.config.loopback_only and not self.allow_remote:
            if not is_loopback_host(host) and not is_local_target(
                url, resolve_dns=True
            ):
                return ScopeDecision(False, "non_loopback_blocked")

        if (
            for_redirect
            and self.config.deny_external_redirects
            and self.target
            and not same_origin(url, self.target)
        ):
            if not (self.allow_remote and not self.config.loopback_only):
                if self.config.loopback_only and not is_loopback_url(url):
                    return ScopeDecision(False, "external_redirect_blocked")
                if self.config.same_origin and not same_origin(url, self.target):
                    return ScopeDecision(False, "cross_origin_redirect_blocked")
                # Scheme flip on same host during redirect still same_origin check above.
                target_parsed = urlparse(self.target)
                if (
                    host == _normalize_hostname(target_parsed.hostname)
                    and parsed.scheme != target_parsed.scheme
                    and parsed.scheme in {"http", "https"}
                ):
                    # Allow http<->https on same host only if configured same host;
                    # still blocked when deny_external and different origin netloc.
                    pass

        if (
            self.config.same_origin
            and self.target
            and not for_redirect
            and parsed.scheme in {"http", "https", "ws", "wss"}
            and not same_origin(
                url.replace("ws://", "http://").replace("wss://", "https://"),
                self.target,
            )
            and not is_loopback_url(
                url.replace("ws://", "http://").replace("wss://", "https://")
            )
        ):
            return ScopeDecision(False, "cross_origin_blocked")

        return ScopeDecision(True, "allowed")

    def allow(self, url: str, *, for_redirect: bool = False) -> bool:
        return self.decide(url, for_redirect=for_redirect).allowed
