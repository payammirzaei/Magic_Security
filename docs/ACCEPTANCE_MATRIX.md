# Acceptance Matrix (STEP 76)

Honest status after Post-50 hardening. Columns are pass only when automated proof exists in CI or local suite.

| Capability | Unit | Integration | E2E | Safe fixture | Vulnerable fixture | CI |
| ---------- | ---- | ----------- | --- | ------------ | ------------------ | -- |
| Network safety / ScanContext transport | PASS | PASS | PARTIAL | n/a | n/a | PASS |
| Scope bypass red-team | PASS | PASS | n/a | n/a | n/a | PASS |
| Request budgets via transport | PASS | PASS | PARTIAL | n/a | n/a | PASS |
| Secret leak / redaction | PASS | PASS | PARTIAL | n/a | n/a | PASS |
| Browser Playwright discovery/XSS | PASS | PASS | PARTIAL | n/a | demo | PARTIAL |
| Local API / dashboard control plane | PASS | PASS | PARTIAL | n/a | n/a | PASS |
| Workflow packs (builtins + cleanup gate) | PASS | PARTIAL | SCAFFOLDED | n/a | demo | PARTIAL |
| Auth identity integrity | PASS | PASS | n/a | n/a | n/a | PASS |
| Finding proof catalog | PASS | n/a | n/a | n/a | n/a | PASS |
| False-positive corpus (safe_app) | PASS | PASS | PASS | PASS | n/a | PASS |
| False-negative corpus (vulnerable_app) | PASS | PASS | PARTIAL | n/a | PASS | PASS |
| Backtesting lifecycle | PASS | PASS | PARTIAL | n/a | n/a | PASS |
| Historical endpoint seeding | PASS | PASS | n/a | n/a | n/a | PASS |
| Remote ownership verification | PASS | PARTIAL | SCAFFOLDED | n/a | n/a | PASS |
| Production-safe profile | PASS | PASS | n/a | n/a | n/a | PASS |
| Dashboard UI (targets/status/findings/coverage/surface/diff) | PARTIAL | PARTIAL | PARTIAL | n/a | n/a | PARTIAL |
| Dependency inventory | PASS | n/a | n/a | n/a | n/a | PASS |
| Diagnostics / observability | PASS | PASS | n/a | n/a | n/a | PASS |
| Perf baselines | PASS | n/a | n/a | synthetic | n/a | PASS |
| Cancellation / recovery | PASS | PARTIAL | SCAFFOLDED | n/a | n/a | PASS |
| Repo framework extraction | PASS | PASS | n/a | fixtures | n/a | PASS |

**Not production-ready** until Browser E2E, Workflow full demo E2E, and live DNS ownership are no longer PARTIAL/SCAFFOLDED.
