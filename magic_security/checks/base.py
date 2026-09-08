from __future__ import annotations

from typing import Protocol

from magic_security.models import Finding, PageSnapshot


class SecurityCheck(Protocol):
    name: str

    def run(self, page: PageSnapshot) -> list[Finding]:
        ...
