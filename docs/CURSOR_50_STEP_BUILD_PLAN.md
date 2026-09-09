# Magic_Security — 50-Step Cursor Implementation Plan

> **Repository:** `payammirzaei/Magic_Security`  
> **Plan type:** executable engineering plan for Cursor Agent  
> **Baseline:** current repository is already around **v1.1**, with a substantial local-first black-box scanner, authenticated contexts, browser testing, evidence-driven findings, stable-ish fingerprints, coverage reporting, and first-generation snapshot/diff security backtesting.  
> **Primary rule:** **Do not rewrite working capabilities just because a cleaner architecture is described here. Migrate incrementally, preserve behavior, and prove every migration with tests.**

---

# 0. Product Mission

Magic_Security is an **evidence-driven security backtesting platform for web applications we own or are explicitly authorized to test**.

The tool should behave like a careful external security engineer:

1. discover the real attack surface;
2. understand what is public, authenticated, role-bound, user-specific, and state-changing;
3. generate safe security hypotheses;
4. establish a baseline;
5. mutate one security assumption at a time;
6. verify meaningful differences;
7. retain minimal and redacted evidence;
8. classify findings correctly;
9. report what was tested and what was not tested;
10. create a repeatable snapshot;
11. compare with previous scans;
12. detect regressions before deployment;
13. later enrich runtime truth with repository and infrastructure context.

The product principle is:

> **No proof → no vulnerability.**

A finding may be:

- **Vulnerability** — the security failure was reproduced.
- **Exposure** — dangerous behavior/surface is observable but exploit impact is not fully proven.
- **Hardening** — defensive configuration should be improved.
- **Observation** — security-relevant signal requiring stronger verification.

Severity and confidence are separate concepts.

---

# 1. Current Repository Reality

Cursor MUST inspect the repository before implementing anything.

The repository already contains modules such as:

- `magic_security/engine.py`
- `magic_security/cli.py`
- `magic_security/models.py`
- `magic_security/crawler.py`
- `magic_security/browser.py`
- `magic_security/browser_security.py`
- `magic_security/auth.py`
- `magic_security/idor.py`
- `magic_security/csrf.py`
- `magic_security/session_security.py`
- `magic_security/injection.py`
- `magic_security/parameter_security.py`
- `magic_security/server_security.py`
- `magic_security/protocol_security.py`
- `magic_security/graphql_security.py`
- `magic_security/client_artifacts.py`
- `magic_security/exposure_pack.py`
- `magic_security/coverage_registry.py`
- `magic_security/fingerprints.py`
- `magic_security/reporting.py`
- `magic_security/backtesting.py`
- `magic_security/checks/`
- a synthetic vulnerable application under `examples/`
- a substantial `tests/` directory.

The existing CLI already supports concepts including:

- HTTP crawling;
- browser mode;
- safe active mode;
- authenticated contexts;
- JSON reports;
- scan snapshots;
- baseline comparison.

Therefore, this plan is an **incremental evolution from the current implementation**, not a greenfield rewrite.

---

# 2. Non-Negotiable Cursor Execution Contract

Cursor must follow these rules for every one of the 50 steps.

## 2.1 Work One Step at a Time

When instructed to execute `STEP N`:

- implement only Step N;
- do not begin Step N+1;
- do not silently introduce unrelated architecture;
- do not perform speculative large rewrites.

If Step N exposes a prerequisite bug, fix only the minimum prerequisite required and document it.

## 2.2 Inspect Before Editing

Before changing files:

1. inspect relevant existing modules;
2. inspect relevant tests;
3. identify existing behavior that must remain compatible;
4. state the intended migration in a short implementation note.

Never assume a capability is missing simply because this document describes it.

## 2.3 Preserve Compatibility

Unless a step explicitly changes a public contract:

- preserve current CLI behavior;
- preserve report fields;
- preserve existing check behavior;
- preserve snapshot compatibility where practical;
- preserve existing tests.

If a schema must change, add an explicit version/migration strategy.

## 2.4 Tests Are Gates

At the end of every step:

```bash
pytest
```

must pass.

If browser-specific tests exist and Playwright is available, run them too.

Never:

- delete a failing test to make the suite green;
- weaken an assertion without explaining why;
- mark a broken test skipped simply to complete the step;
- fake a test with hard-coded success;
- claim success without running the relevant tests.

## 2.5 Add Tests for Every New Contract

Every new component must have:

- positive tests;
- negative tests;
- boundary tests;
- false-positive regression tests where relevant.

Security verification logic should normally have:

- vulnerable fixture;
- safe fixture;
- expected evidence;
- proof failure case.

## 2.6 Safe-by-Default Rules

Until the dedicated remote-target steps are complete:

- active scanning remains localhost/loopback by default;
- no arbitrary third-party scanning;
- no brute forcing;
- no credential stuffing;
- no uncontrolled concurrency;
- no destructive state changes;
- no cloud metadata probing;
- no arbitrary private-network SSRF probing;
- no command execution;
- no persistent payloads;
- no automatic purchase/payment/account deletion actions;
- no secret values in reports.

Remote active scanning may only be introduced after explicit scope and authorization controls exist.

## 2.7 Minimal Sensitive Data

Do not serialize:

- passwords;
- session tokens;
- bearer tokens;
- API keys;
- reset tokens;
- OTP values;
- complete sensitive responses;
- private uploaded file contents.

Prefer:

- field names;
- redacted excerpts;
- hashes;
- fingerprints;
- lengths;
- booleans;
- synthetic canaries.

## 2.8 Commit/Completion Format

At the end of each step Cursor should return:

```text
STEP N COMPLETE

Implemented:
- ...

Files changed:
- ...

Tests added/updated:
- ...

Commands run:
- ...

Result:
- ...

Known limitations:
- ...

Ready for STEP N+1: YES/NO
```

---

# 3. Target Architecture

Do not move everything at once. Gradually evolve toward:

```text
magic_security/
├── cli/
├── engine/
│   ├── orchestrator.py
│   ├── context.py
│   ├── scope.py
│   ├── budgets.py
│   ├── transport.py
│   └── cancellation.py
│
├── discovery/
│   ├── http.py
│   ├── browser.py
│   ├── javascript.py
│   ├── openapi.py
│   ├── graphql.py
│   ├── indexes.py
│   └── historical.py
│
├── surface/
│   ├── models.py
│   ├── normalize.py
│   ├── graph.py
│   └── fingerprints.py
│
├── packs/
│   ├── exposure/
│   ├── browser/
│   ├── injection/
│   ├── server/
│   ├── api/
│   ├── graphql/
│   ├── websocket/
│   ├── auth/
│   ├── authorization/
│   ├── workflow/
│   └── session/
│
├── evidence/
│   ├── models.py
│   ├── redact.py
│   ├── confidence.py
│   ├── normalize.py
│   └── dedupe.py
│
├── backtesting/
│   ├── snapshot.py
│   ├── history.py
│   ├── baseline.py
│   ├── diff.py
│   └── policy.py
│
├── workflows/
├── repo_analysis/
├── infrastructure/
├── persistence/
├── reporting/
└── api/
```

Compatibility modules may temporarily re-export classes/functions from old paths.

---

# 4. The 50 Implementation Steps

---

## STEP 1 — Freeze the Existing v1.1 Baseline

### Goal

Create a trustworthy record of current behavior before refactoring.

### Work

- Run the complete existing test suite.
- Run the synthetic vulnerable application and one representative full scan.
- Save a canonical test report under a test fixture location.
- Save a canonical compact snapshot.
- Record current CLI options and exit behavior.
- Record current package version.
- Record test count and major capability list.
- Add `docs/CURRENT_STATE.md`.

The document must clearly distinguish:

- implemented;
- partially implemented;
- planned;
- intentionally unsupported.

### Tests

No production behavior should change in this step.

### Definition of Done

- Existing tests are green.
- A reproducible baseline report exists.
- A baseline snapshot exists.
- `CURRENT_STATE.md` reflects actual code, not only the old master plan.
- No feature implementation was added.

---

## STEP 2 — Create a Capability and Coverage Inventory

### Goal

Prevent duplicate work and expose blind spots.

### Work

Create a machine-readable capability registry, for example:

```text
docs/CAPABILITY_MATRIX.yaml
```

Each security capability should include:

- stable capability ID;
- category;
- current module;
- scan modes required;
- prerequisites;
- proof standard;
- finding kind;
- current maturity;
- test file;
- known gaps.

Include the current 42-category coverage registry, but separate broad categories from concrete checks.

Example:

```yaml
- id: browser.dom_xss
  category: xss
  mode: [browser, active]
  maturity: verified
  proof: runtime_canary_execution
  source: magic_security/browser_security.py
```

### Definition of Done

- Every current major check is inventoried.
- Every current coverage category points to real checks or explicitly says why coverage is partial.
- No category claims “Fully Tested” merely because a single variant exists.

---

## STEP 3 — Align Versioning, Documentation, and CLI Reality

### Goal

Remove contradictions between README, master plan, and implementation.

### Work

- Update `docs/MASTER_PLAN.md` current-state references from obsolete v1.0 assumptions to current v1.1 reality.
- Keep historical notes where useful, but label them.
- Define semantic version policy.
- Define snapshot schema version separately from package version.
- Define report schema version separately from package version.
- Add `magic-security --version`.
- Add a small `version.py` or equivalent single source of truth.

### Tests

Test:

- CLI version output;
- package version consistency;
- report/snapshot schema version fields.

### Definition of Done

There is one unambiguous answer to:

- scanner version;
- report schema version;
- snapshot schema version.

---

## STEP 4 — Introduce Typed Scan Configuration

### Goal

Stop passing a growing set of unrelated booleans through the engine.

### Work

Introduce a typed configuration object such as:

```python
ScanConfig
```

It should contain:

- target;
- profile;
- max pages;
- browser enabled;
- active enabled;
- auth contexts;
- scope;
- budgets;
- timeouts;
- reporting options;
- snapshot options.

Do not remove current CLI flags.

The CLI translates current flags into `ScanConfig`.

### Tests

- CLI compatibility.
- Default config parity with current behavior.
- Invalid combinations fail clearly.

### Definition of Done

`ScannerEngine` can receive one normalized configuration object without changing observable scan results.

---

## STEP 5 — Introduce ScanContext

### Goal

Create one immutable-ish runtime context shared by packs.

### Work

Create `ScanContext` containing:

- scan ID;
- target identity;
- config;
- scope;
- request budget;
- transport;
- auth contexts;
- scan start time;
- cancellation state;
- metrics collector;
- evidence/redaction services.

Do not immediately refactor every check.

Migrate a small representative path first, then provide compatibility.

### Definition of Done

- ScanContext exists.
- At least discovery and one active pack use it.
- Existing public behavior remains unchanged.
- Tests show context isolation between scans.

---

## STEP 6 — Centralize Scope Enforcement

### Goal

Every outbound request must obey the same scope decision.

### Work

Implement an explicit scope model:

- allowed schemes;
- allowed hosts;
- allowed ports;
- allowed paths;
- denied paths;
- same-origin policy;
- redirect policy;
- browser request policy.

Default local profile:

- loopback only.

Scope checks must occur:

- before request dispatch;
- after redirects;
- on browser-observed navigation/request;
- on WebSocket URLs.

Create a `ScopeDecision` with a reason.

### Tests

Include:

- localhost allowed;
- alternate loopback forms;
- external host blocked;
- redirect to external blocked;
- deceptive hostnames blocked;
- IPv6 loopback behavior;
- denied path behavior.

### Definition of Done

No active request path bypasses scope enforcement.

---

## STEP 7 — Add Global Request Budgets

### Goal

Bound scanner impact.

### Work

Create shared budgets:

- total requests;
- requests per endpoint;
- requests per pack;
- maximum response bytes;
- maximum redirects;
- maximum pages;
- maximum active mutations;
- maximum browser navigations.

When exhausted:

- stop the relevant operation safely;
- record coverage degradation;
- do not silently claim tests completed.

### Tests

Simulate budget exhaustion and verify:

- scan stays consistent;
- coverage reports incomplete;
- no extra requests are sent.

### Definition of Done

Every network-capable pack consumes centralized budget tokens.

---

## STEP 8 — Add Concurrency and Rate Control

### Goal

Prevent accidental request bursts and make scans reproducible.

### Work

Implement:

- global concurrency semaphore;
- per-host concurrency;
- configurable request rate;
- backoff on 429/503;
- cancellation-aware waiting.

Default values must be conservative.

### Tests

Use deterministic fake transport tests to confirm limits.

### Definition of Done

No pack creates uncontrolled independent concurrency.

---

## STEP 9 — Centralize HTTP Transport

### Goal

Make outbound HTTP behavior auditable and enforceable.

### Work

Create one transport abstraction wrapping `httpx`.

It should handle:

- scope;
- budgets;
- rate limiting;
- redirect checks;
- response byte limits;
- common timeout policy;
- user agent;
- request IDs;
- redacted structured request metadata;
- cancellation.

Do not store sensitive request bodies by default.

### Migration

Gradually migrate modules. Temporary adapters are acceptable.

### Definition of Done

All active HTTP checks eventually use the central transport; direct `httpx` use outside approved low-level modules is blocked by tests/lint check.

---

## STEP 10 — Centralize Redaction

### Goal

Guarantee sensitive data handling independent of individual pack authors.

### Work

Create a redaction service for:

- headers;
- cookies;
- query parameters;
- JSON fields;
- form fields;
- text excerpts;
- URLs.

Recognize secret-like keys and PII-like values.

Provide:

- redacted value;
- fingerprint/hash;
- original length;
- optional category.

### Tests

Create aggressive fixtures containing fake:

- passwords;
- bearer tokens;
- API keys;
- email/phone/address patterns;
- reset/OTP values.

Ensure report, logs, snapshot, exceptions, and evidence never contain originals.

### Definition of Done

A scanner-level regression test scans all generated output for seeded fake secrets and finds none.

---

## STEP 11 — Standardize Evidence Objects

### Goal

Make findings comparable and explainable.

### Work

Introduce a normalized evidence schema.

Suggested concepts:

```text
check_id
proof_type
baseline_summary
mutation_summary
observed_result
redacted_artifacts
confidence
sensitive_values_stored=false
```

Do not force all old checks to migrate at once.

Add adapters from legacy evidence strings.

### Definition of Done

At least three diverse check families emit standardized evidence while reports remain readable.

---

## STEP 12 — Standardize the Check Interface

### Goal

Turn checks into predictable units instead of ad-hoc functions.

### Work

Define a check protocol/interface containing:

- stable `check_id`;
- title;
- category;
- required modes;
- prerequisites;
- risk class;
- whether state mutation is possible;
- whether workflow authorization is required;
- proof condition;
- evidence policy;
- default coverage outcome;
- async execution entry point.

### Definition of Done

Existing checks can be progressively wrapped without a full rewrite.

---

## STEP 13 — Build a Check Registry

### Goal

Know exactly which checks are loaded and why.

### Work

Create a registry that:

- registers checks by stable ID;
- rejects duplicates;
- supports pack grouping;
- resolves prerequisites;
- can list enabled/disabled/skipped checks;
- exposes metadata to coverage reporting.

Add CLI:

```bash
magic-security checks list
```

### Definition of Done

Coverage can distinguish:

- executed;
- skipped by profile;
- skipped due to missing auth;
- skipped due to missing browser;
- blocked by safety;
- failed.

---

## STEP 14 — Add Pack Isolation and Failure Containment

### Goal

One broken check must not corrupt the scan.

### Work

For each pack/check:

- capture typed failures;
- isolate timeouts;
- distinguish tool error from security result;
- record partial coverage;
- continue when safe.

Never convert internal failure into “no vulnerability found.”

### Definition of Done

Synthetic tests intentionally crash one check and verify the overall scan completes with an explicit coverage failure.

---

## STEP 15 — Structured Scanner Logging and Metrics

### Goal

Make scanner behavior debuggable without leaking sensitive data.

### Work

Add structured events for:

- scan start/end;
- discovery phase;
- pack start/end;
- request budget use;
- scope denial;
- timeout;
- check error;
- finding emitted;
- coverage degradation.

Add aggregate metrics:

- requests;
- pages;
- endpoints;
- checks executed;
- verified findings;
- duration per pack.

### Definition of Done

Logs are useful for debugging and pass the secret redaction regression test.

---

## STEP 16 — Build Attack Surface Graph v1

### Goal

Move beyond a flat URL list.

### Work

Create graph node types:

- page;
- endpoint;
- parameter;
- form;
- JS asset;
- source map;
- GraphQL endpoint;
- WebSocket;
- auth context;
- resource ID;
- cookie/storage key.

Create edge types:

- links_to;
- loads;
- calls;
- accepts;
- discovered_from;
- visible_to;
- owns;
- requires_auth.

Build the graph from existing crawl results.

### Definition of Done

Current reports still work, while the graph can answer:

- which page discovered this endpoint?
- which parameters belong to it?
- which contexts can see it?

---

## STEP 17 — Improve Endpoint and Parameter Normalization

### Goal

Reduce duplicate testing without merging semantically different routes.

### Work

Improve normalization for:

- numeric IDs;
- UUIDs;
- hashes;
- pagination;
- locale prefixes;
- cache-busting query values;
- Next.js dynamic routes;
- common REST resource patterns.

Preserve:

- HTTP method;
- parameter location;
- auth context distinctions;
- meaningful route semantics.

### Tests

Include false-merge and false-split cases.

### Definition of Done

The scanner tests fewer duplicates while maintaining or improving detection coverage.

---

## STEP 18 — Historical Attack Surface Seeding

### Goal

Retest stale or hidden endpoints that disappeared from navigation.

### Work

When a compatible previous snapshot exists:

- load historical normalized endpoints;
- keep them clearly marked as historical;
- optionally retest safe reads;
- never treat historical presence as current presence without verification.

### Definition of Done

A route removed from navigation but still reachable can be rediscovered from scan history.

---

## STEP 19 — Deep Browser Discovery Hardening

### Goal

Improve SPA and runtime attack-surface visibility.

### Work

Enhance Playwright discovery for:

- SPA route transitions;
- fetch/XHR;
- GraphQL requests;
- dynamically loaded chunks;
- WebSockets;
- redirects;
- frames;
- service-worker-visible network activity where practical.

Do not randomly click destructive controls.

Navigation may use safe anchor/button heuristics only if the action is classified as non-mutating.

### Definition of Done

Browser discovery adds measurable surface beyond raw HTTP crawling on synthetic fixtures.

---

## STEP 20 — JavaScript Artifact Analysis v2

### Goal

Improve client-side discovery and security analysis beyond fragile regex alone.

### Work

Introduce structured parsing where practical for JavaScript/TypeScript artifacts.

Detect:

- API paths;
- GraphQL paths;
- WebSocket endpoints;
- client-side routes;
- source maps;
- dangerous sinks;
- browser-controlled sources;
- postMessage handlers;
- internal topology references;
- secret-like material without storing secret values.

### Definition of Done

Keep heuristics as fallback, but use parsed structure for high-confidence cases.

---

## STEP 21 — Passive External Exposure Pack v2

### Goal

Professionalize externally visible misconfiguration and leakage detection.

### Work

Consolidate checks for:

- source-control metadata;
- backup artifacts;
- config files;
- source maps;
- debug/status endpoints;
- verbose framework errors;
- server/version disclosure;
- exposed manifests;
- indexing metadata;
- robots/sitemap-discovered sensitive paths;
- sensitive values in URLs;
- GET forms carrying secrets;
- mixed content.

Every check must specify whether it is:

- verified exposure;
- hardening;
- observation.

### Definition of Done

No generic missing-header warning is promoted to high severity without context.

---

## STEP 22 — Browser Security Verification Pack v2

### Goal

Strengthen user-side runtime verification.

### Work

Consolidate and test:

- reflected XSS proof;
- DOM XSS proof;
- HTML injection;
- client-side open redirect;
- browser storage posture;
- postMessage origin validation signals;
- clickjacking posture;
- CSP posture;
- insecure mixed content;
- WebSocket scheme exposure.

Use harmless synthetic canaries.

### Definition of Done

Static candidates and runtime-proven vulnerabilities are never conflated.

---

## STEP 23 — Server-Side Safe Verification Pack v2

### Goal

Unify bounded active server checks.

### Work

Migrate current safe checks into standardized pack contracts:

- database error trigger behavior;
- arithmetic-only SSTI proof;
- inert response-header injection proof;
- path traversal using known non-secret marker files;
- controlled host-header influence;
- bounded safe SSRF callback using scanner-owned endpoint;
- protocol method observations.

No destructive or persistence payloads.

### Definition of Done

Each check has a baseline, one controlled mutation, a proof rule, and minimal evidence.

---

## STEP 24 — API Security Pack v1

### Goal

Increase API-specific black-box coverage.

### Work

Use discovered/OpenAPI endpoints to test, safely:

- inconsistent authentication;
- undocumented public routes;
- unexpected methods;
- content-type handling differences;
- excessive response fields/signals;
- sensitive query parameters;
- verbose validation errors;
- pagination boundary behavior;
- stale versioned endpoints;
- safe mass-assignment candidates only where a disposable workflow later authorizes mutation.

Do not generically mutate production objects.

### Definition of Done

Read-only API checks can run generically; state-changing checks remain gated behind workflow mode.

---

## STEP 25 — GraphQL Pack v2

### Goal

Move beyond introspection-only analysis.

### Work

Support bounded checks for:

- anonymous introspection;
- verbose errors;
- anonymous sensitive field access;
- authentication boundary differences;
- field-level authorization using configured users;
- safe query depth/complexity posture with strict caps;
- alias/batch behavior classification;
- subscription endpoint discovery.

No denial-of-service style stress testing.

### Definition of Done

GraphQL coverage records precisely which checks were actually exercised.

---

## STEP 26 — WebSocket Security Pack v1

### Goal

Turn WebSocket discovery into security verification.

### Work

Safely test:

- endpoint existence;
- authentication requirement;
- origin enforcement;
- anonymous connection behavior;
- authenticated-vs-anonymous message differences;
- authorization for read-only subscriptions where deterministic and safe.

Message-level state mutation requires workflow configuration.

### Definition of Done

CSWSH-like posture is only labeled verified when actual cross-origin acceptance behavior is demonstrated under controlled conditions.

---

## STEP 27 — Authentication Context Model v2

### Goal

Make multi-account scanning reliable.

### Work

Standardize auth contexts:

- name;
- role;
- login mechanism;
- headers/cookies;
- browser state;
- expected identity marker;
- disposable flag.

Validate that contexts are actually different after authentication.

Detect expired/broken sessions before authorization testing.

### Definition of Done

IDOR/authz tests cannot accidentally compare the same logged-in identity twice.

---

## STEP 28 — Authentication Security Pack v2

### Goal

Strengthen login boundary testing without brute force.

### Work

Add bounded verification for:

- invalid credential baseline;
- account enumeration signals;
- session cookie posture;
- session establishment behavior;
- alternate auth endpoints;
- login/token endpoint rate behavior;
- synthetic SQL/NoSQL auth-bypass probes only against the configured synthetic login flow;
- authentication boundary inconsistencies.

### Definition of Done

No real credential guessing is performed.

---

## STEP 29 — Authorization Matrix Engine v2

### Goal

Model authorization explicitly.

### Work

Represent:

```text
Subject
Role
Action
Resource
Ownership
Expected Decision
Observed Decision
```

Generate a read-only authorization matrix across configured contexts.

Use IDs learned from each user's own responses.

No ID brute force.

### Definition of Done

The report can explain exactly which subject accessed which other subject's resource and why the finding is considered verified.

---

## STEP 30 — BOLA/IDOR Verification v2

### Goal

Make cross-account authorization testing robust and low-noise.

### Work

Support:

- path identifiers;
- query identifiers;
- nested resource identifiers;
- common opaque IDs;
- semantic response comparison;
- negative controls;
- ownership confidence.

Avoid false positives caused by:

- public objects;
- shared resources;
- identical generic responses;
- cached responses.

### Definition of Done

Every verified BOLA finding includes a baseline and cross-account proof without storing sensitive object data.

---

## STEP 31 — Declarative Workflow Schema

### Goal

Enable safe testing of state-changing classes.

### Work

Define YAML/JSON workflow schema supporting:

- context;
- request;
- body/template;
- variable extraction;
- assertions;
- resource ownership;
- cleanup;
- safety classification.

Example concepts:

```yaml
create:
read:
mutate:
verify:
cleanup:
```

Do not execute workflows yet beyond parser/validator tests.

### Definition of Done

Invalid or unsafe workflow definitions fail before network activity.

---

## STEP 32 — Workflow Runner and Variable Engine

### Goal

Execute explicitly declared workflows deterministically.

### Work

Implement:

- step sequencing;
- variable extraction from JSON/header/location;
- templating;
- assertions;
- context switching;
- timeouts;
- structured execution record;
- cancellation.

Every workflow has an explicit lifecycle.

### Definition of Done

A synthetic create/read/delete workflow executes and records redacted evidence.

---

## STEP 33 — Disposable Resource Lifecycle and Cleanup

### Goal

Prevent test artifacts from accumulating.

### Work

Add resource tracking:

- created resource ID fingerprint;
- owning context;
- cleanup endpoint;
- cleanup state.

Cleanup should run:

- after success;
- after assertion failure;
- after downstream check failure;
- during graceful cancellation when possible.

### Definition of Done

End-to-end tests confirm no synthetic disposable resources remain after workflow tests.

---

## STEP 34 — State-Changing Authorization Workflow Pack

### Goal

Safely verify write/delete BOLA using disposable objects.

### Work

With explicitly configured disposable workflows:

1. user A creates a temporary object;
2. scanner records ownership;
3. user B attempts an authorized test mutation;
4. scanner verifies server-side state;
5. scanner restores/deletes test object.

### Definition of Done

No generic production object is mutated.

---

## STEP 35 — Stored XSS Workflow Pack

### Goal

Verify stored XSS without leaving persistent content.

### Work

Use only configured disposable create/read/delete lifecycle.

- store harmless canary markup;
- visit rendering location using browser;
- verify canary execution only;
- clean up.

No cookie/storage extraction, callbacks, persistence beyond test lifecycle, or user-targeted payloads.

### Definition of Done

Stored XSS can be proven on the synthetic app and safely cleaned.

---

## STEP 36 — Upload Security Workflow Pack

### Goal

Safely test user-visible file upload handling.

### Work

Only with explicit workflow configuration and harmless fixtures.

Test:

- extension validation;
- MIME handling;
- content sniffing;
- harmless SVG active-content behavior;
- authorization on uploaded objects;
- public exposure;
- filename normalization;
- storage path leakage;
- overwrite behavior.

Do not upload executable server-side code.

### Definition of Done

All uploaded fixtures are deleted during cleanup.

---

## STEP 37 — Session Lifecycle Workflow Pack

### Goal

Verify session behaviors generic crawling cannot prove.

### Work

With disposable test accounts:

- login;
- capture session fingerprint only;
- logout;
- verify invalidation;
- login again;
- verify rotation;
- test concurrent-session posture if configured;
- test remember-me behavior if configured.

### Definition of Done

Reports never contain raw session identifiers.

---

## STEP 38 — Backtesting Schema v2

### Goal

Harden the existing v1.1 snapshot model rather than replacing it blindly.

### Work

Audit current `backtesting.py`.

Split responsibilities gradually into:

- snapshot model;
- serialization;
- history;
- diff;
- policy.

Add explicit schema version.

Snapshot should include:

- target identity;
- scanner version;
- scan profile;
- modes;
- normalized findings;
- attack surface;
- coverage;
- evidence fingerprints;
- timestamps;
- optional commit/deployment metadata.

### Definition of Done

Existing v1.1 snapshots are either loadable or rejected with a precise migration/version error.

---

## STEP 39 — Persistent Local Scan History and Baselines

### Goal

Turn one-off `--baseline file` usage into real scan history.

### Work

Implement filesystem-first target history:

```text
.magic-security/
  targets/
    <target-id>/
      scans/
      baselines/
```

Add CLI concepts:

```bash
magic-security target add
magic-security scan
magic-security history
magic-security baseline set
magic-security diff
```

Preserve existing direct target invocation as compatibility.

### Definition of Done

A user can scan the same target repeatedly without manually managing snapshot filenames.

---

## STEP 40 — Regression Policy Engine and Exit Codes

### Goal

Make backtesting useful in automation.

### Work

Policy should support:

- fail on new verified critical/high;
- warn on new verified medium;
- optional fail on reintroduced;
- optional fail on worsened;
- ignore unchanged debt;
- minimum required coverage;
- required browser/auth modes;
- maximum allowed scan failures.

Produce deterministic exit codes.

### Definition of Done

Intentional new high-severity verified finding fails policy while unchanged existing debt does not necessarily fail.

---

## STEP 41 — Reporting v2: Terminal + Canonical JSON

### Goal

Make reports decision-focused.

### Work

Terminal report should prioritize:

1. scan validity;
2. coverage equivalence;
3. new/reintroduced/worsened verified issues;
4. new exposures;
5. resolved issues;
6. attack surface changes;
7. existing findings.

JSON must become canonical and schema-versioned.

Include reproducibility metadata without secrets.

### Definition of Done

“0 findings” and “0 tests executed” are impossible to confuse.

---

## STEP 42 — Standalone HTML Security Report

### Goal

Create a report a developer or manager can inspect without the CLI.

### Work

Generate a standalone HTML file with:

- executive summary;
- regressions;
- findings;
- severity/confidence;
- evidence;
- remediation;
- coverage;
- attack surface diff;
- scan metadata.

Do not require a server.

Avoid embedding sensitive raw responses.

### Definition of Done

HTML report renders from the same canonical report model as JSON/terminal.

---

## STEP 43 — Remote Authorized Target Registry

### Goal

Prepare safe testing of owned staging/production systems.

### Work

Add target registry fields:

- target ID;
- base URL;
- environment;
- allowed hosts;
- denied paths;
- authorization state;
- verification method;
- production-safe limits.

States:

```text
UNVERIFIED
VERIFIED
SUSPENDED
EXPIRED
```

Support safe ownership mechanisms such as:

- DNS TXT challenge;
- well-known challenge;
- trusted local registration;
- repository/deployment linkage.

### Rule

Remote **active** mode must require a verified target unless an explicit trusted-local test override is used.

### Definition of Done

Unverified remote target cannot run active packs.

---

## STEP 44 — Production-Safe Remote Profile

### Goal

Allow useful scanning of owned production sites with strong limits.

### Work

Create a production-safe profile:

- passive discovery;
- bounded safe GET verification;
- browser discovery;
- conservative rate;
- no generic state mutation;
- no workflow mode unless separately allowed;
- explicit path denylist;
- response byte limits;
- strict timeout;
- stop conditions.

### Definition of Done

The remote scanner cannot silently expand to another host or perform undeclared mutations.

---

## STEP 45 — Repository Adapter Framework

### Goal

Add source context without replacing runtime truth.

### Work

Create adapter interface for local/connected repository snapshots.

Normalize:

- repository ID;
- commit;
- framework;
- routes;
- auth controls;
- config findings;
- dependency manifests;
- source locations.

Repo findings are a separate evidence source.

### Rule

A static code smell must never automatically become a verified runtime vulnerability.

### Definition of Done

A mock repository adapter can enrich a scan without changing black-box proof semantics.

---

## STEP 46 — Framework-Aware Source Analysis

### Goal

Support the stacks most relevant to this project.

### Priority

1. Next.js / React;
2. Laravel / PHP;
3. FastAPI / Python;
4. Express / Node.

### Work

For each supported framework, extract where feasible:

- routes;
- methods;
- middleware;
- auth guards/policies;
- environment/config patterns;
- public assets;
- source maps/config;
- dangerous debug settings.

Start with route extraction + auth mapping, then expand.

### Definition of Done

Runtime endpoints can be compared against likely source routes for at least Next.js and Laravel, with tests.

---

## STEP 47 — Repository Security Pack

### Goal

Find source-only risks and correlate them with runtime evidence.

### Work

Add safe static analysis for:

- secret-like values, storing only fingerprint/location;
- dependency manifests;
- dangerous framework config;
- Dockerfile/container config;
- CI workflow risks;
- permissive CORS settings;
- debug settings;
- public storage config;
- risky auth middleware omissions.

Correlate:

```text
runtime endpoint ↔ source route ↔ auth middleware
```

### Definition of Done

Reports distinguish:

- runtime verified vulnerability;
- runtime exposure;
- source finding;
- correlated evidence.

---

## STEP 48 — Local API + Persistence Layer

### Goal

Turn the engine into a reusable local service without coupling scanning logic to HTTP.

### Work

Add a small FastAPI control plane:

```text
POST /targets
GET  /targets
POST /scans
GET  /scans/{id}
GET  /scans/{id}/findings
GET  /scans/{id}/diff
GET  /scans/{id}/coverage
```

Add persistence abstraction.

Start SQLite for tests if useful, but production local architecture should support PostgreSQL.

Entities:

- targets;
- scans;
- findings;
- finding instances;
- coverage;
- baselines;
- attack surface nodes/edges;
- workflow definitions;
- repositories;
- deployments.

### Definition of Done

CLI and API use the same engine/application services.

---

## STEP 49 — Local Dashboard + CI Regression Gate

### Goal

Make Magic_Security usable in daily development.

### Dashboard

Minimum screens:

- Targets;
- Latest Security Status;
- New Regressions;
- Findings;
- Attack Surface;
- Coverage;
- Scan History;
- Baseline Diff.

Avoid vanity charts.

### CI

Add GitHub Actions integration concept:

```text
PR
→ preview/staging target
→ scan
→ baseline from main
→ policy
→ PR summary
→ pass/fail
```

CI must fail on policy, not “any finding exists.”

Coverage regression must be able to fail CI.

### Definition of Done

A synthetic PR introducing a verified high regression is blocked; resolving it passes; lowering required coverage cannot silently pass.

---

## STEP 50 — Professional Release Hardening and Acceptance Suite

### Goal

Prove the system is ready to be trusted as a serious owned-site security backtester.

### Work

Create a final acceptance suite covering all critical product promises.

#### A. Reliability

- deterministic results;
- stable fingerprints;
- repeatable snapshots;
- check failure isolation;
- cancellation;
- timeout behavior;
- no corrupted scan state.

#### B. Safety

- scope bypass regression tests;
- redirect escape tests;
- DNS/host normalization edge cases;
- request-budget enforcement;
- remote authorization gating;
- production-safe profile;
- workflow mutation gating;
- cleanup guarantees.

#### C. Privacy

Seed fake secrets and PII across:

- HTML;
- JSON;
- headers;
- cookies;
- URLs;
- logs;
- browser storage;
- auth contexts.

Verify no sensitive values appear in:

- JSON reports;
- HTML reports;
- snapshots;
- logs;
- exceptions;
- database rows.

#### D. Detection

For every supported verified vulnerability type:

- vulnerable fixture;
- safe fixture;
- proof success;
- proof failure;
- false-positive regression.

#### E. Backtesting

Automated sequence:

1. clean baseline;
2. introduce vulnerability;
3. detect `NEW`;
4. fix vulnerability;
5. detect `RESOLVED`;
6. reintroduce vulnerability;
7. detect `REINTRODUCED`;
8. reduce coverage;
9. detect non-equivalent scan.

#### F. Performance

Set documented budgets for:

- small app;
- medium app;
- browser scan;
- authenticated scan;
- full workflow scan.

Avoid a meaningless “checks per second” target.

#### G. Documentation

Ship:

- architecture;
- quick start;
- scan profiles;
- safe-use rules;
- auth context guide;
- workflow guide;
- remote target verification;
- repository mode;
- backtesting/baseline guide;
- CI guide;
- report schema;
- snapshot schema;
- troubleshooting.

### Final Definition of Done

Magic_Security may call itself a **professional external security backtesting platform for authorized web applications** only when all of the following are true:

- explicit scope is enforced centrally;
- request impact is bounded;
- remote active scans require authorization state;
- sensitive values are centrally redacted;
- findings have stable IDs;
- verified vulnerabilities contain reproducible proof;
- confidence and severity remain separate;
- “not found” and “not tested” are distinct;
- attack surface is modeled and diffed;
- scan coverage is modeled and diffed;
- authentication contexts are validated;
- read-only BOLA/IDOR is reliably verified;
- state-changing checks require declared disposable workflows;
- cleanup is enforced;
- snapshot history and baselines are first-class;
- regression policy can gate CI;
- source analysis enriches but never overrides runtime truth;
- failures are explicit;
- the acceptance suite passes.

---

# 5. Required Quality Gates Across All 50 Steps

These rules apply globally.

## 5.1 No False Confidence

The scanner must never say:

```text
Secure
```

simply because no findings were emitted.

Prefer:

```text
No verified vulnerabilities were observed in the checks that completed.
```

and display coverage.

## 5.2 Every Check Has a Proof Contract

For every security check document:

```text
Prerequisites
Baseline
Mutation
Proof condition
Failure condition
Evidence retained
Risk class
Cleanup requirement
Coverage result
```

## 5.3 Every Network Operation Has a Safety Contract

Before dispatch:

```text
Is the target in scope?
Is the method allowed?
Is the check enabled?
Does it require workflow authorization?
Is the target authorization state sufficient?
Is request budget available?
Is concurrency budget available?
Could state change?
Could external interaction occur?
Could the response be large/sensitive?
```

## 5.4 Every Schema Is Versioned

Version independently:

- JSON report schema;
- scan snapshot schema;
- workflow schema;
- API schema where needed.

## 5.5 No Giant Rewrite

During migration:

- create new package;
- move one behavior;
- keep compatibility import;
- test parity;
- migrate callers;
- remove old path only when no caller depends on it.

---

# 6. Suggested Milestone Releases

The 50 steps may map to releases approximately as follows.

| Release | Steps | Meaning |
|---|---:|---|
| v1.1.x | 1–3 | Current-state stabilization |
| v1.2 | 4–10 | Core safety and runtime contracts |
| v1.3 | 11–15 | Evidence/check architecture |
| v1.4 | 16–20 | Attack-surface and discovery engine |
| v1.5 | 21–26 | Professional external verification packs |
| v1.6 | 27–30 | Auth/authz/BOLA hardening |
| v1.7 | 31–37 | Declarative workflow engine |
| v1.8 | 38–42 | Full security backtesting UX |
| v1.9 | 43–47 | Remote authorized + repo-aware mode |
| v2.0 | 48–50 | API/dashboard/CI + professional acceptance |

Version numbers are guidance, not a requirement. Do not bump a release until its acceptance conditions pass.

---

# 7. Core Security Coverage Expected by the End

The final platform should have explicit status for at least the following families:

### Discovery and Exposure

- public routes;
- hidden routes;
- robots/sitemap;
- OpenAPI/Swagger;
- GraphQL;
- JS-discovered routes;
- browser runtime API calls;
- source maps;
- public source-control metadata;
- backup/config artifacts;
- debug/status endpoints;
- internal topology leakage;
- sensitive URL values;
- insecure GET forms;
- mixed content;
- server/framework disclosure.

### Browser

- reflected HTML injection;
- reflected XSS;
- DOM XSS;
- stored XSS through workflow;
- CSP posture;
- clickjacking posture;
- browser storage posture;
- postMessage posture;
- client redirects;
- WebSockets;
- active-content upload rendering.

### API / Server

- CORS;
- credentialed protected CORS;
- JSONP;
- verbose errors;
- database error behavior;
- safe SSTI proof;
- response-header injection;
- path traversal/LFI proof;
- bounded safe SSRF callback;
- host-header influence;
- protocol method exposure;
- authenticated caching;
- rate-limit behavior;
- content-type confusion;
- authentication inconsistencies.

### Auth / Authorization

- authentication boundaries;
- invalid login baseline;
- session cookie posture;
- session invalidation workflow;
- session rotation workflow;
- account enumeration signals;
- BOLA/IDOR read;
- state-changing BOLA/IDOR via disposable workflow;
- role comparison;
- CSRF posture;
- disposable CSRF workflow where configured.

### Advanced Protocols

- GraphQL auth/field behavior;
- WebSocket authentication;
- WebSocket origin enforcement;
- read-only subscription authorization.

### Repository-Aware

- routes;
- auth middleware/policies;
- source-only secret candidates;
- dangerous config;
- dependency manifests;
- Docker config;
- CI config;
- runtime-to-source correlation.

Coverage must remain honest: some classes will always require explicit workflows, repository access, infrastructure access, or human review.

---

# 8. Things Magic_Security Must Never Pretend to Fully Automate

Even after Step 50, do not claim universal coverage of:

- complex business logic;
- financial abuse;
- multi-stage social engineering;
- destructive race conditions;
- cloud/IAM configuration not visible to configured adapters;
- supply-chain trust beyond available manifests/advisories;
- arbitrary server-side command execution proof;
- production payment workflows;
- every authorization invariant;
- every possible XSS context;
- every possible SQL injection variant;
- every private infrastructure weakness.

The correct output is often:

```text
Partial
Requires Auth
Requires Workflow
Requires Repo Access
Requires Infrastructure Access
Not Tested
```

That honesty is a feature.

---

# 9. Cursor Master Prompt

Paste the following instruction to Cursor before asking it to start Step 1:

```text
You are implementing Magic_Security using docs/CURSOR_50_STEP_BUILD_PLAN.md.

Treat that document as the execution contract.

Important:
1. Inspect the current repository before changing anything.
2. The repository already contains a working v1.1 scanner. This is an incremental migration, not a rewrite.
3. Execute exactly ONE numbered step at a time.
4. Do not begin the next step until the current step's Definition of Done is satisfied.
5. Preserve existing behavior unless the current step explicitly changes a contract.
6. Run the complete relevant test suite after every step.
7. Never delete/weaken tests merely to make them pass.
8. Add positive, negative, boundary, and false-positive tests for new security logic.
9. Keep local/loopback-only active scanning as the default until the remote authorization steps are implemented.
10. Never add destructive scanning, brute forcing, credential stuffing, cloud-metadata probing, arbitrary internal-network probing, or secret serialization.
11. Every verified vulnerability must have reproducible evidence.
12. Every untested/failed prerequisite must reduce or mark coverage rather than silently producing a clean result.
13. At completion of each step print:
   - Implemented
   - Files changed
   - Tests added/updated
   - Commands run
   - Result
   - Known limitations
   - Ready for next step: YES/NO
14. Stop after completing the requested step.

First read:
- README.md
- docs/MASTER_PLAN.md
- docs/CURRENT_STATE.md if present
- this 50-step plan
- pyproject.toml
- magic_security/engine.py
- magic_security/models.py
- magic_security/cli.py
- magic_security/backtesting.py
- magic_security/fingerprints.py
- magic_security/reporting.py
- relevant test files.

Then execute only the step I request.
```

---

# 10. Recommended Human Workflow

Use Cursor like this:

```text
Read docs/CURSOR_50_STEP_BUILD_PLAN.md and execute STEP 1 only.
```

Review the result.

Then:

```text
Execute STEP 2 only. First verify STEP 1 still passes.
```

Continue sequentially.

For every fifth step, also ask Cursor for:

```text
Run the complete test suite and audit Steps N-4 through N for regressions, unfinished TODOs, duplicated logic, direct network calls that bypass central safety, and sensitive-data leakage. Fix only regressions related to completed steps. Do not start the next step.
```

This creates ten mini-release gates across the 50-step build.

---

# 11. Final Product Statement

At the end of this plan, Magic_Security should not behave like a payload cannon or a checklist scanner.

It should behave like this:

```text
Discover deeply
→ model the attack surface
→ understand the security context
→ establish a baseline
→ generate a safe hypothesis
→ mutate one assumption
→ verify meaningful impact
→ retain minimal evidence
→ classify confidence and severity independently
→ report coverage honestly
→ create an immutable security snapshot
→ compare with the known-good baseline
→ surface only meaningful regressions
→ enrich with source/deployment context where available
```

The desired developer experience is:

```text
Your latest deployment introduced:
- 1 NEW verified HIGH authorization regression
- 1 NEW MEDIUM browser exposure

Resolved:
- 1 previous credentialed CORS issue

Coverage:
- Browser: equivalent
- Authenticated: equivalent
- Authorization: equivalent
- Workflow: equivalent

Attack surface:
- 2 new endpoints
- 1 new parameter
- no out-of-scope requests

No other verified regressions were observed in the checks that completed.
```

That is the standard Cursor should build toward.
