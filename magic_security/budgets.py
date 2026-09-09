"""Global request budgets (STEP 7)."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from magic_security.config import BudgetConfig

_GLOBAL_REASONS = frozenset(
    {
        "max_total_requests",
        "max_response_bytes",
        "max_active_mutations",
        "max_pages",
        "max_browser_navigations",
    }
)


class BudgetExhausted(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class RequestBudget:
    config: BudgetConfig
    total_requests: int = 0
    requests_per_endpoint: dict[str, int] = field(default_factory=dict)
    active_mutations: int = 0
    browser_navigations: int = 0
    pages: int = 0
    exhausted_reasons: list[str] = field(default_factory=list)

    @property
    def exhausted(self) -> bool:
        return any(reason in _GLOBAL_REASONS for reason in self.exhausted_reasons)

    def _endpoint_key(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _mark(self, reason: str) -> None:
        if reason not in self.exhausted_reasons:
            self.exhausted_reasons.append(reason)

    def consume_request(
        self,
        url: str,
        *,
        response_bytes: int = 0,
        mutation: bool = False,
    ) -> bool:
        """Return True if allowed and counted; False if blocked by budget."""
        if self.exhausted:
            return False

        if self.total_requests >= self.config.max_total_requests:
            self._mark("max_total_requests")
            return False

        key = self._endpoint_key(url)
        if (
            self.requests_per_endpoint.get(key, 0)
            >= self.config.max_requests_per_endpoint
        ):
            self._mark("max_requests_per_endpoint")
            return False

        if response_bytes > self.config.max_response_bytes:
            self._mark("max_response_bytes")
            return False

        if mutation:
            if self.active_mutations >= self.config.max_active_mutations:
                self._mark("max_active_mutations")
                return False
            self.active_mutations += 1

        self.total_requests += 1
        self.requests_per_endpoint[key] = (
            self.requests_per_endpoint.get(key, 0) + 1
        )
        return True

    def consume_page(self, max_pages: int) -> bool:
        limit = (
            self.config.max_pages
            if self.config.max_pages is not None
            else max_pages
        )
        if self.pages >= limit:
            self._mark("max_pages")
            return False
        self.pages += 1
        return True

    def consume_browser_navigation(self) -> bool:
        if self.browser_navigations >= self.config.max_browser_navigations:
            self._mark("max_browser_navigations")
            return False
        self.browser_navigations += 1
        return True

    def coverage_degradation(self) -> dict[str, object]:
        return {
            "budget_exhausted": self.exhausted
            or bool(self.exhausted_reasons),
            "reasons": list(self.exhausted_reasons),
            "total_requests": self.total_requests,
            "pages": self.pages,
            "active_mutations": self.active_mutations,
            "browser_navigations": self.browser_navigations,
        }
