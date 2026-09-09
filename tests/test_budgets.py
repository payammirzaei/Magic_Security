from __future__ import annotations

from magic_security.budgets import RequestBudget
from magic_security.config import BudgetConfig


def test_budget_exhaustion_stops_extra_requests():
    budget = RequestBudget(BudgetConfig(max_total_requests=2))
    assert budget.consume_request("http://127.0.0.1/a")
    assert budget.consume_request("http://127.0.0.1/b")
    assert not budget.consume_request("http://127.0.0.1/c")
    assert budget.exhausted
    assert budget.total_requests == 2
    degradation = budget.coverage_degradation()
    assert degradation["budget_exhausted"] is True
    assert "max_total_requests" in degradation["reasons"]


def test_per_endpoint_budget():
    budget = RequestBudget(
        BudgetConfig(max_total_requests=100, max_requests_per_endpoint=1)
    )
    assert budget.consume_request("http://127.0.0.1/api")
    assert not budget.consume_request("http://127.0.0.1/api?x=1")
    assert budget.consume_request("http://127.0.0.1/other")
