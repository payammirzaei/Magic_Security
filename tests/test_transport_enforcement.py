from __future__ import annotations

import re
from pathlib import Path


def test_no_direct_httpx_async_client_outside_transport():
    root = Path(__file__).resolve().parents[1] / "magic_security"
    offenders: list[str] = []
    allowed = {"transport.py"}
    pattern = re.compile(r"httpx\.AsyncClient\s*\(")

    for path in root.rglob("*.py"):
        if path.name in allowed:
            continue
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path.relative_to(root.parent)))

    assert offenders == [], f"Direct httpx.AsyncClient usage found: {offenders}"
