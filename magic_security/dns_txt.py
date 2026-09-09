"""DNS helpers for ownership verification."""

from __future__ import annotations

import os
import struct
from typing import Iterable


def dns_txt_live_lookup_enabled() -> bool:
    """Live DNS TXT is opt-in via MAGIC_SECURITY_DNS_TXT=1.

    Default remains disabled so CI and offline installs fail closed with an
    explicit message rather than a half-working resolver.
    """
    return os.environ.get("MAGIC_SECURITY_DNS_TXT", "").strip() in {
        "1",
        "true",
        "TRUE",
        "yes",
        "YES",
    }


def _encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    out = bytearray()
    for part in parts:
        raw = part.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label: {part!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _parse_txt_rdata(rdata: bytes) -> str:
    chunks: list[str] = []
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        chunks.append(rdata[i : i + length].decode("utf-8", errors="replace"))
        i += length
    return "".join(chunks)


def lookup_txt_records(name: str, *, nameserver: str = "8.8.8.8") -> list[str]:
    """Minimal UDP DNS TXT lookup (no third-party dependency)."""
    import random
    import socket

    qname = name if name.endswith(".") else name + "."
    txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(qname) + struct.pack("!HH", 16, 1)  # TXT IN
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(packet, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return []
    r_txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if r_txid != txid or (flags & 0x000F) != 0:
        return []

    offset = 12

    def _skip_name(buf: bytes, off: int) -> int:
        while True:
            if off >= len(buf):
                raise ValueError("truncated DNS name")
            length = buf[off]
            if length == 0:
                return off + 1
            if length & 0xC0 == 0xC0:
                return off + 2
            off += 1 + length

    for _ in range(qdcount):
        offset = _skip_name(data, offset)
        offset += 4

    records: list[str] = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(
            "!HHIH",
            data[offset : offset + 10],
        )
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 16:
            try:
                records.append(_parse_txt_rdata(rdata))
            except Exception:
                continue
    return records


def records_contain_challenge(
    records: Iterable[str],
    *,
    expected: str,
    target_id: str,
) -> bool:
    joined = " ".join(records)
    if expected and expected in joined:
        return True
    if f"magic-security-verification={target_id}" in joined:
        return True
    token = expected.split("=", 1)[-1] if expected else ""
    return bool(token and token in joined) or target_id in joined
