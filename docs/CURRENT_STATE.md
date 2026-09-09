# Magic_Security — Current State (Frozen Baseline)

> **Frozen for:** STEPs 1–50 of `CURSOR_50_STEP_BUILD_PLAN.md`  
> **Package version:** `1.3.0` (`magic_security.__version__` / `pyproject.toml`)  
> **Freeze date:** 2026-09-09  
> **Rule:** This document describes **actual repository behavior**, not the aspirational master plan.

---

## 1. What the product is today

Magic_Security is a **local-first, evidence-driven black-box web security scanner** with security backtesting (snapshots + baseline diffs), optional repository enrichment, a local API/dashboard, and CI regression gating.

Primary principle already enforced in reporting:

> **No proof → no vulnerability** (findings are split into Vulnerability / Exposure / Hardening / Observation-style signals)

Default safety posture:

- remote targets are **blocked** unless `allow_remote=True` (CLI stays localhost by default)
- remote **active** scans require a **VERIFIED** target-registry entry (or trusted-local override)
- source findings never auto-promote to verified runtime vulnerabilities
- no secret values intended to be written into reports
- no object-ID brute force; IDOR uses IDs learned from each test account

---

## 2. Package / CLI reality

### Version

- Scanner / package: `1.3.0` (`magic_security.version.SCANNER_VERSION`)
- Report schema: `2` (`REPORT_SCHEMA_VERSION`)
- Snapshot schema: `2` (`SNAPSHOT_SCHEMA_VERSION`; v1 snapshots still load via migration)

**Semantic version policy:** bump `SCANNER_VERSION` / `pyproject.toml` for
user-visible scanner changes. Bump `REPORT_SCHEMA_VERSION` or
`SNAPSHOT_SCHEMA_VERSION` only when those document shapes break consumers.
Package version and schema versions are independent.

### Entry points

- Console script: `magic-security` → `magic_security.cli:main`
- Module: `python -m magic_security`
- Optional API + dashboard: `magic-security serve` (extra `[api]`; UI from `web/dist`)

### CLI options (actual)

| Argument | Default | Effect |
|----------|---------|--------|
| `target` | required | Local target URL |
| `--max-pages` | `100` | Same-origin crawl page budget |
| `--browser` | off | Playwright anonymous + authenticated discovery; browser XSS verification |
| `--active` | off | Safe active external/server verification packs |
| `--auth-contexts` | none | JSON test-user contexts (≥2) enabling auth/session/IDOR packs |
| `--workflows` | none | Workflow file/dir for disposable state-changing packs |
| `--persist-history` | off | Write scans under `.magic-security/targets/<id>/scans` |
| `--fail-on-policy` | off | Exit `1` on new verified high/critical regressions |
| `--json` | none | Write canonical JSON report (schema v2) |
| `--html` | none | Write standalone HTML report from the same model |
| `--repo` | none | Local repository path for source enrichment |
| `--snapshot` | none | Write compact backtesting snapshot |
| `--baseline` | none | Compare current snapshot against a previous snapshot |

Subcommands: `serve`, `checks list`, `target add|verify|list`, `history`, `baseline set`, `diff`, `scan`.

### Exit behavior (actual)

| Code | When |
|------|------|
| `0` | Scan completed (or policy warnings only) |
| `1` | Regression policy failed (`--fail-on-policy` / `diff`) |
| `2` | Configuration/runtime errors: non-local target, browser unavailable, bad auth contexts, bad/unreadable baseline snapshot, unverified remote active |
| argparse help/errors | Standard argparse exits (`0` for `--help`, `2` for usage errors) |

---

## 3. Test baseline

Commands run in a local `.venv` with `pip install -e ".[dev,browser]"` and Playwright Chromium installed:

```text
pytest -q
→ 142 passed, 1 skipped
```

(The skip is the optional FastAPI API test when `[api]` is not installed.)

Representative full demo scan:

```text
magic-security http://127.0.0.1:8000 \
  --browser --active \
  --auth-contexts examples/auth_contexts.example.json \
  --json report.json --html report.html --snapshot snap.json
```

Canonical historical artifacts (v1.1 era):

- `tests/fixtures/baseline/v1.1_canonical_report.json`
- `tests/fixtures/baseline/v1.1_canonical_snapshot.json`
- `tests/fixtures/baseline/MANIFEST.json`

Operator docs: `docs/QUICK_START.md`

---

## 4. Major capability list (by maturity)

### Implemented (working in code + covered by tests / demo)

**Discovery**

- HTTP crawl (`crawler.py`)
- Index discovery (robots/sitemap)
- Browser enrichment (`browser.py`)
- JS / client artifact analysis
- OpenAPI / GraphQL surface hints
- Historical seeding from baseline snapshots

**Checks / packs**

- Passive headers/cookies/exposure
- Exposure / browser / server packs
- API, GraphQL, WebSocket security packs
- Auth / session / CSRF posture
- Authz matrix + hardened IDOR/BOLA
- Injection / parameter / protocol / behavior packs
- Declarative workflows (write BOLA, stored XSS, upload, session)
- Repository security pack (source-only; secret fingerprints)

**Platform**

- `ScanConfig` / `ScanContext`, scope, budgets, rate, transport, redaction
- CheckSpec registry + pack_runner + coverage registry
- Report v2 (terminal + JSON) with scan validity / regressions
- Standalone HTML report
- Snapshot v2 + migrate v1; history store; baseline diff; policy gate
- Target registry (UNVERIFIED / VERIFIED / SUSPENDED / EXPIRED)
- Production-safe remote profile
- Repository adapters + framework-aware analysis (Next.js, Laravel, FastAPI, Express)
- Local SQLite persistence + optional FastAPI control plane
- Local dashboard HTML writer + CI regression workflow example

### Intentionally unsupported (by design today)

- Scanning arbitrary remote/third-party hosts from the CLI without verification
- Brute-force credential stuffing / object-ID guessing
- Cloud metadata / arbitrary private-network SSRF probing
- Destructive production mutations, payment/purchase actions, account deletion
- Claiming “Fully Tested” for broad categories from a single variant
- Storing passwords, session tokens, full private response bodies, or secret values in reports
- Replacing human pentests or guaranteeing “the app is secure”
- Auto-promoting static source smells to verified runtime vulnerabilities

---

## 5. Repository layout (actual)

```text
magic_security/          # flat scanner package (v1.3)
  cli.py, engine.py, models.py, crawler.py, browser.py, ...
  reporting.py / reporting_html.py
  workflow_*.py, history.py, policy.py
  target_registry.py, profiles.py
  repo_adapter.py, framework_analysis.py, repo_security.py
  persistence.py, api.py, dashboard.py
  *_pack*.py / api_security.py / websocket_security.py / authz_matrix.py
  checks/                # passive header/cookie/exposure checks
  backtesting.py         # snapshot schema v2 + v1 migrate
examples/
  vulnerable_app.py
  auth_contexts.example.json
tests/                   # 142+ tests (1 optional API skip without fastapi)
tests/fixtures/baseline/ # historical v1.1 report + snapshot
docs/
  MASTER_PLAN.md
  CURSOR_50_STEP_BUILD_PLAN.md
  CURRENT_STATE.md       # this file
  CAPABILITY_MATRIX.yaml
  QUICK_START.md
.github/workflows/
  test.yml
  security-regression.yml
```

Python: `>=3.11`  
Core deps: `httpx`, `beautifulsoup4`  
Optional: `playwright` (`[browser]`), `fastapi`/`uvicorn` (`[api]`)  
Dev: `pytest`, `pytest-asyncio`

---

## 6. Known limitations at freeze time

1. Successful scans exit `0` unless `--fail-on-policy` is set, even when verified critical findings exist.
2. Some finding identities still use `legacy.*` fingerprints when no title pattern matches.
3. Request budgets exist but large active+browser+auth scans remain request-heavy.
4. Async tests require `pytest-asyncio` (installed via `[dev]`).
5. Baseline fixtures are historical references; regenerating them will change timestamps and volatile surface details.
6. Package structure remains a flat module layout (not the multi-package architecture sketched in the master plan).
7. STEP 50 acceptance is covered by focused regression/policy/scope tests + docs, not a full A–G formal matrix harness.
8. Remote DNS TXT / well-known ownership challenges are modeled in the registry; full automated challenge flows remain minimal.
9. **STEP 51 (network safety):** HTTP packs use `open_secure_transport` + bound `ScanContext`. Browser gating is pre-navigation / route abort (`assert_url_in_scope`) — not full CDP request interception with budget accounting for every browser subresource. Playwright itself is outside `SecureTransport`. Demo app / DNS utilities are not scanner network paths.

---

## 7. Ready for incremental evolution

STEPs **1–50** of the Cursor build plan are implemented in-tree at scanner **1.3.0**.

**STEP 51** network safety audit: HTTP outbound paths inherit ScopePolicy / RequestBudget / RateLimiter via `open_secure_transport` and engine `bind_scan_context`. Browser/WebSocket active navigation is scope-gated (`PARTIAL` vs full request-budgeted browser transport).

Next: STEP 52+ from the Post-50 hardening audit.

Further work should treat this document as the behavioral baseline and evolve via tests + version/schema bumps rather than silent rewrites.
