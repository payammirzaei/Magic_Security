# Magic_Security — Master Product Plan, Architecture, and Roadmap

> **Status:** Living design document  
> **Current implementation:** v1.0 local-first black-box scanner  
> **Long-term product:** Evidence-driven security backtesting platform for web applications, APIs, and their deployment/repository context

---

## 1. Executive Summary

Magic_Security is being built to answer a practical problem:

> Modern applications — especially fast-moving, AI-assisted, and vibe-coded applications — can look correct while still containing serious security defects that are visible from the outside.

The goal is not to create another noisy vulnerability scanner that throws hundreds of generic warnings at a developer. The goal is to build a system that behaves more like a careful external security engineer:

1. discover what the application actually exposes;
2. understand the attack surface;
3. test observable security assumptions;
4. verify a weakness before calling it a vulnerability;
5. preserve safe, minimal evidence;
6. explain what was tested and what was not tested;
7. compare scans over time;
8. detect security regressions after code changes or deployments;
9. later combine black-box evidence with repository and infrastructure context.

The core product principle is:

> **No proof → no vulnerability.**

Magic_Security should eventually become a **security backtesting platform** for all applications we own or are explicitly authorized to test.

Instead of asking only:

> “Does this site have vulnerabilities right now?”

the platform should also answer:

> “What changed since the last known-good version?”

> “Did the latest deployment introduce a new externally exploitable weakness?”

> “Did our security coverage become weaker?”

> “Which findings are proven, which are exposures, and which are merely hardening opportunities?”

> “Which classes of bugs cannot be tested without authentication, workflows, repository access, or infrastructure access?”

---

# 2. Why We Are Building This

AI-assisted development dramatically increases implementation speed, but it also changes the failure mode of software development.

A vibe-coded application may:

- render correctly;
- pass happy-path manual testing;
- have acceptable UI/UX;
- successfully call its backend;
- deploy without errors;
- appear production-ready;

while still containing security mistakes such as:

- missing authorization checks;
- unintended public API routes;
- leaked source maps;
- sensitive values in URLs;
- weak CORS configuration;
- exposed debug endpoints;
- IDOR/BOLA;
- reflected or DOM XSS;
- unsafe redirects;
- insecure session cookies;
- accidental backup/config exposure;
- cache leakage between users;
- unsafe GraphQL configuration;
- exposed internal topology;
- missing rate controls;
- inconsistent authentication boundaries;
- dangerous GET actions;
- sensitive browser storage;
- source-control metadata exposure;
- environment/configuration leakage.

The underlying problem is not that AI-generated code is always insecure. The problem is that development becomes much faster than careful security review.

Magic_Security therefore acts as an automated adversarial review layer.

---

# 3. Product Vision

The final system should support three major security perspectives.

## Layer A — External / Black-Box Security

The scanner behaves like an external user or attacker who does not have source-code access.

It observes:

- public pages;
- browser behavior;
- network requests;
- APIs;
- forms;
- JavaScript;
- source maps;
- HTTP behavior;
- authentication boundaries;
- application behavior across multiple user accounts.

This remains the foundation of Magic_Security because these are the defects an external user may actually exploit.

## Layer B — Repository-Aware Security

When repository access is available, Magic_Security should enrich black-box findings with:

- source-level route discovery;
- authorization implementation review;
- secret scanning;
- dependency analysis;
- dangerous framework configuration;
- Docker configuration;
- CI/CD configuration;
- source-only security smells;
- mapping runtime endpoints to source files.

Repository access should **improve confidence and coverage**, not replace black-box verification.

## Layer C — Deployment / Infrastructure Security

When deployment access is explicitly configured, the system can inspect:

- deployment metadata;
- container configuration;
- environment configuration;
- exposed ports;
- TLS/domain settings;
- reverse-proxy configuration;
- cloud/service configuration;
- deployment drift;
- public-vs-private service boundaries.

These layers should eventually converge into one report.

---

# 4. Current State — v1.0

The current repository already contains a meaningful black-box scanner.

v1.0 currently includes:

- HTTP crawling;
- browser crawling with Playwright;
- authenticated browser contexts;
- OpenAPI discovery;
- robots.txt discovery;
- sitemap.xml discovery;
- endpoint normalization;
- endpoint classification;
- response fingerprinting;
- finding deduplication;
- exposed-file probes;
- source-map discovery;
- client artifact analysis;
- reflected HTML injection verification;
- reflected XSS verification;
- DOM XSS verification;
- GraphQL security checks;
- CORS checks;
- authenticated CORS checks;
- rate-limit behavior checks;
- authenticated cache behavior checks;
- session-cookie analysis;
- CSRF posture mapping;
- IDOR/BOLA pairwise read verification;
- server-side parameter checks;
- path traversal/LFI verification;
- bounded SSRF callback verification;
- protocol-security checks;
- sensitive endpoint discovery;
- sensitive URL/form detection;
- mixed-content detection;
- JSONP checks;
- user-visible surface analysis;
- explicit security coverage reporting;
- JSON reports;
- automated tests;
- GitHub Actions test execution.

The engine is intentionally restricted to localhost/loopback by default.

This is the correct safety posture for the early development phase.

---

# 5. What Magic_Security Is Not

Magic_Security should not become:

- a blind payload cannon;
- a brute-force framework;
- a destructive exploitation framework;
- a scanner that reports theoretical CVEs without relevance;
- a tool that marks every missing header as “critical”;
- a replacement for human penetration testing;
- a source-code-only static analyzer;
- a tool that pretends 100% security coverage is possible;
- a system that downloads or stores sensitive data unnecessarily.

A professional security tool must be honest about uncertainty.

---

# 6. Core Product Principles

## 6.1 Evidence First

A finding must contain evidence appropriate to its classification.

A vulnerability should require a reproducible security failure.

Examples:

- XSS → actual harmless browser execution was observed.
- IDOR → user A could retrieve user B's resource using a resource identifier learned from B.
- CORS → a protected authenticated response was readable from an attacker-controlled origin condition.
- SSTI → a harmless arithmetic expression was evaluated server-side.
- CRLF → a controlled inert response header was injected.
- traversal → known marker content was observed only after the traversal mutation.
- auth bypass → invalid baseline authentication failed while a test mutation produced a meaningful authenticated success signal.

## 6.2 Coverage Honesty

The report must state whether a category was:

- Fully Tested;
- Partially Tested;
- Passive Only;
- Requires Auth;
- Requires Config;
- Requires Repo Access;
- Requires Infrastructure Access;
- Not Applicable.

We should never imply that a security category was comprehensively tested when only one variant was inspected.

## 6.3 Safe by Default

Active testing must be bounded.

Default behavior should avoid:

- destructive actions;
- real-account modification;
- arbitrary internal-network SSRF;
- cloud metadata probes;
- brute force;
- credential stuffing;
- large downloads;
- uncontrolled concurrency;
- persistence;
- file execution;
- production data mutation.

## 6.4 Minimal Sensitive Data

Reports should store the smallest evidence required to prove a finding.

Prefer:

- fingerprints;
- field names;
- booleans;
- hashes;
- lengths;
- redacted excerpts;
- synthetic canary values.

Avoid:

- session tokens;
- passwords;
- complete private responses;
- personal data;
- uploaded file contents;
- secret values.

## 6.5 Black-Box First

If the application behaves insecurely at runtime, that runtime behavior is the strongest evidence.

Repository and infrastructure access are later enrichment layers.

## 6.6 Regression-Oriented

A security scanner gives a snapshot.

A security backtester gives a timeline.

Magic_Security should eventually detect:

- new findings;
- resolved findings;
- reintroduced findings;
- severity changes;
- attack-surface expansion;
- newly exposed endpoints;
- newly exposed parameters;
- weaker security headers;
- lost authentication boundaries;
- newly public resources;
- reduced scan coverage.

---

# 7. Primary User Journey

The long-term normal flow should be:

~~~text
Register Target
      ↓
Define Safe Scope
      ↓
Configure Optional Test Accounts / Workflows
      ↓
Run Discovery
      ↓
Build Attack Surface
      ↓
Run Passive Analysis
      ↓
Run Safe Active Verification
      ↓
Run Browser Verification
      ↓
Run Auth / Authorization Verification
      ↓
Optional Workflow Verification
      ↓
Optional Repo-Aware Analysis
      ↓
Optional Infrastructure Analysis
      ↓
Normalize + Deduplicate Evidence
      ↓
Risk / Confidence Scoring
      ↓
Create Scan Snapshot
      ↓
Compare Against Baseline
      ↓
Generate Report
      ↓
CI Gate / Developer Action
~~~

---

# 8. Target Operating Modes

Magic_Security should support explicit scan profiles instead of one giant scan mode.

## 8.1 Passive

No meaningful application mutation.

Suitable for:

- discovery;
- headers;
- visible leaks;
- public files;
- JavaScript analysis;
- source maps;
- robots/sitemap;
- route observation;
- browser network discovery.

## 8.2 Safe Active

Uses bounded synthetic probes.

Suitable for:

- reflected injection;
- safe SSTI arithmetic;
- response splitting checks;
- CORS;
- redirect behavior;
- parameter mutations;
- protocol checks;
- bounded rate-limit classification.

## 8.3 Browser

Uses Playwright to evaluate behavior impossible to verify reliably with HTTP alone.

Suitable for:

- DOM XSS;
- client redirects;
- storage posture;
- runtime network discovery;
- runtime WebSocket discovery;
- browser-only routes;
- postMessage behavior.

## 8.4 Authenticated

Uses dedicated test accounts.

Suitable for:

- authentication boundary mapping;
- protected endpoint discovery;
- IDOR/BOLA;
- cookie/session analysis;
- authenticated cache;
- protected CORS;
- role comparison.

## 8.5 Workflow

Uses explicitly configured disposable workflows.

Suitable for security classes that cannot be tested safely by generic crawling.

Examples:

- stored XSS;
- file upload;
- password reset;
- MFA;
- logout invalidation;
- session rotation;
- state-changing authorization;
- CSRF proof;
- business invariants;
- race conditions.

## 8.6 Repo-Aware

Adds source analysis.

## 8.7 Infrastructure-Aware

Adds deployment/configuration analysis.

---

# 9. High-Level Architecture

~~~mermaid
flowchart TD
    A[Target + Scan Profile] --> B[Scope & Safety Controller]
    B --> C[Discovery Orchestrator]

    C --> D[HTTP Crawler]
    C --> E[Browser Crawler]
    C --> F[OpenAPI / GraphQL Discovery]
    C --> G[Index / Artifact Discovery]
    C --> H[Authenticated Discovery]

    D --> I[Attack Surface Graph]
    E --> I
    F --> I
    G --> I
    H --> I

    I --> J[Passive Security Packs]
    I --> K[Active Verification Packs]
    I --> L[Auth / Authorization Packs]
    I --> M[Workflow Packs]

    N[Repository Adapter] --> O[Repo-Aware Security Packs]
    P[Infrastructure Adapter] --> Q[Infra Security Packs]

    J --> R[Evidence Store]
    K --> R
    L --> R
    M --> R
    O --> R
    Q --> R

    R --> S[Finding Normalizer]
    S --> T[Deduplication]
    T --> U[Risk + Confidence Engine]
    U --> V[Scan Snapshot]
    V --> W[Baseline Comparator]
    W --> X[JSON / HTML / Dashboard / CI]
~~~

---

# 10. The Attack Surface Model

The scanner should stop treating a site as only a list of URLs.

The internal model should become an **attack surface graph**.

Nodes may include:

- page;
- endpoint;
- parameter;
- form;
- JavaScript asset;
- source map;
- GraphQL endpoint;
- WebSocket endpoint;
- authentication context;
- role;
- discovered resource identifier;
- cookie;
- browser storage key;
- workflow state;
- repository file;
- deployment service.

Edges may include:

- page links to page;
- page loads asset;
- page calls endpoint;
- endpoint accepts parameter;
- user owns resource;
- endpoint requires role;
- workflow creates resource;
- source file implements endpoint;
- service deploys repository commit.

This enables much stronger reasoning than isolated probes.

Example:

~~~text
User A
  └── owns ──> Order 817
                 ↑
                 │ returned by
                 │
             GET /api/orders/817

User B
  └── calls same endpoint with 817
                 ↓
        response contains Order 817
                 ↓
        VERIFIED BOLA / IDOR
~~~

---

# 11. Discovery Strategy

Discovery quality determines scanner quality.

A vulnerability cannot be tested if the relevant endpoint is never discovered.

Discovery should combine multiple sources.

## 11.1 HTTP Crawl

Extract:

- links;
- forms;
- actions;
- methods;
- inputs;
- query parameters;
- scripts;
- redirects;
- content types.

## 11.2 Browser Crawl

Capture:

- dynamically rendered routes;
- fetch/XHR requests;
- GraphQL requests;
- WebSockets;
- SPA navigation;
- client-side route generation.

## 11.3 JavaScript Discovery

Parse or heuristically identify:

- API paths;
- internal routes;
- WebSocket URLs;
- GraphQL paths;
- upload endpoints;
- admin paths;
- feature-flag endpoints.

Later, AST-based JavaScript analysis should replace fragile regex-only discovery where appropriate.

## 11.4 Standards / Metadata Discovery

Inspect:

- robots.txt;
- sitemap.xml;
- OpenAPI;
- Swagger;
- GraphQL;
- common framework metadata.

## 11.5 Authenticated Discovery

Run discovery from every configured security context.

Example contexts:

~~~text
anonymous
customer_a
customer_b
staff
admin
~~~

Different users may see entirely different attack surfaces.

## 11.6 Historical Discovery

Future scans should also reuse previous attack-surface snapshots.

If an endpoint disappears from navigation but remains reachable, Magic_Security should still know that it existed and can retest it.

This is important for stale API routes.

---

# 12. Verification Packs

The scanner should be organized into independent security packs.

Each pack should define:

- prerequisites;
- discovery signals;
- safe probe strategy;
- proof condition;
- evidence policy;
- severity rules;
- confidence rules;
- cleanup behavior;
- coverage status.

---

# 13. Browser Security Pack

Coverage should include:

- reflected XSS;
- DOM XSS;
- stored XSS through configured workflows;
- unsafe browser storage;
- insecure postMessage behavior;
- open/client redirect;
- clickjacking posture;
- CSP weaknesses;
- mixed content;
- insecure form targets;
- WebSocket discovery;
- unsafe websocket scheme;
- browser-only endpoint discovery.

A browser finding should distinguish:

~~~text
Static candidate
Runtime signal
Verified execution
~~~

---

# 14. Authentication Security Pack

Generic authentication scanning is not enough.

The scanner should support explicit authentication workflows.

Future coverage:

- login boundary validation;
- logout invalidation;
- session rotation;
- session fixation;
- remember-me behavior;
- reset-token behavior;
- reset-token leakage;
- reset-token reuse;
- MFA bypass workflows;
- alternate authentication endpoints;
- role transition behavior;
- account enumeration;
- synthetic invalid credential behavior;
- rate controls.

For production systems, high-risk tests should use dedicated disposable accounts.

---

# 15. Authorization / BOLA / IDOR Pack

This is one of the most important areas for vibe-coded APIs.

The system should model:

~~~text
Subject
Action
Resource
Ownership
Role
Expected Decision
Observed Decision
~~~

Instead of brute-forcing IDs, the preferred strategy is:

1. authenticate as test user A;
2. discover IDs legitimately visible to A;
3. authenticate as test user B;
4. discover IDs legitimately visible to B;
5. attempt safe cross-user reads;
6. compare semantic response fingerprints;
7. report only proven cross-account access.

Later workflow mode can add safe state-changing authorization tests using disposable resources.

Examples:

- edit another user's profile;
- delete another user's temporary object;
- change another user's cart;
- access admin action from staff;
- access hidden API from lower role.

These should never be attempted generically without explicit workflow safety configuration.

---

# 16. API Security Pack

Coverage should include:

- undocumented endpoints;
- inconsistent auth;
- excessive data exposure;
- BOLA;
- broken function-level authorization;
- mass-assignment candidates;
- unsafe methods;
- content-type confusion;
- weak validation;
- verbose errors;
- sensitive query parameters;
- pagination abuse signals;
- batch endpoint behavior;
- versioned stale endpoints;
- dangerous legacy APIs.

OpenAPI schemas should be used to improve parameter generation and expected-type reasoning.

---

# 17. Injection Pack

Injection testing should remain evidence-driven.

Families:

- reflected HTML injection;
- XSS;
- SQL-related behavior;
- NoSQL-related authentication behavior;
- SSTI;
- response-header injection;
- command-injection candidates;
- LDAP/XPath-style candidates where relevant;
- GraphQL argument abuse.

For higher-risk classes such as command injection, the system should only use non-destructive proof mechanisms under explicit configuration.

---

# 18. SSRF Pack

Current behavior correctly limits callback verification.

Future SSRF testing should have safety levels.

## Level 1 — Scanner-Owned Callback

Safe default.

## Level 2 — User-Configured Test Service

A private disposable service explicitly provided for verification.

## Level 3 — Infrastructure-Aware Validation

Only when the user explicitly configures internal test resources.

Magic_Security should not automatically probe cloud metadata or arbitrary internal services.

---

# 19. File Handling / Upload Pack

Generic file upload testing is unsafe without lifecycle control.

A future upload workflow should define:

~~~yaml
workflow:
  name: avatar_upload
  create:
    endpoint: /api/profile/avatar
  allowed_test_files:
    - harmless-image
    - harmless-svg
  fetch:
    endpoint_template: /uploads/{id}
  cleanup:
    endpoint_template: /api/profile/avatar/{id}
~~~

Potential checks:

- extension validation;
- MIME validation;
- content sniffing;
- SVG/script behavior;
- public object exposure;
- authorization on uploaded objects;
- filename/path handling;
- storage path leakage;
- overwrite behavior;
- active-content serving.

No executable payload should be required for useful coverage.

---

# 20. WebSocket Pack

Future verified coverage:

- endpoint discovery;
- authentication requirement;
- origin enforcement;
- cross-site WebSocket hijacking posture;
- authorization after connection;
- message-level object authorization;
- sensitive message leakage;
- unauthenticated subscriptions.

A safe realtime workflow format will be required.

---

# 21. GraphQL Pack

Coverage should evolve beyond introspection.

Future checks:

- anonymous introspection;
- detailed errors;
- field-level authorization;
- object authorization;
- mutation authorization;
- alias/batch abuse;
- excessive depth;
- excessive complexity;
- sensitive schema exposure;
- unauthenticated subscriptions.

DoS-style depth/complexity testing must remain bounded.

---

# 22. Business Logic Pack

Business logic cannot be solved by random payload generation.

It requires invariants.

Example invariant:

~~~text
A coupon may be applied at most once per order.
~~~

or:

~~~text
User A must never be able to change User B's delivery address.
~~~

or:

~~~text
The final charged amount must equal the server-calculated order total.
~~~

Magic_Security should eventually accept declarative invariants and workflows.

This turns business-security tests into repeatable backtests.

---

# 23. Race Condition Pack

Race testing should only run against configured disposable workflows.

Examples:

- duplicate coupon use;
- duplicate withdrawal in test systems;
- repeated order confirmation;
- duplicate resource creation;
- idempotency failure.

The engine should:

1. establish a baseline;
2. create a disposable test state;
3. send a bounded concurrent request group;
4. verify invariant violation;
5. clean up.

Never run generic concurrent state mutation against arbitrary production endpoints.

---

# 24. Repository-Aware Analysis

This is a major future milestone.

Repository access should provide several capabilities.

## 24.1 Route Extraction

Understand framework routes directly from source.

Examples:

- Laravel;
- Next.js;
- Express;
- FastAPI;
- Django;
- Rails;
- Spring.

Then compare:

~~~text
Routes in source
vs.
Routes seen externally
~~~

Interesting cases:

- source route unexpectedly public;
- route deployed but not linked;
- endpoint visible externally but absent from expected source;
- stale deployment.

## 24.2 Authorization Mapping

Search for:

- middleware;
- policies;
- guards;
- role checks;
- ownership checks;
- route groups;
- controller-level authorization.

Then correlate them with runtime tests.

## 24.3 Secret Scanning

Find likely secrets without copying them into reports.

Store:

- file;
- line;
- secret type;
- fingerprint/hash;
- exposure context.

## 24.4 Dependency / Supply-Chain Analysis

Inspect:

- package-lock.json;
- pnpm lockfiles;
- composer.lock;
- requirements;
- poetry;
- Docker images;
- GitHub Actions.

Later integrate current vulnerability databases.

## 24.5 Dangerous Configuration

Examples:

- debug enabled;
- permissive CORS;
- production source maps;
- unsafe cookie settings;
- wildcard trusted proxies;
- weak framework security flags;
- public storage configuration.

---

# 25. Infrastructure-Aware Analysis

This comes after the scanner and repository layers are stable.

Potential adapters:

- Railway;
- GitHub Actions;
- Docker;
- common VPS/Nginx setups;
- Cloudflare;
- AWS;
- ArvanCloud;
- Cloudways.

We should not build every integration at once.

The first goal should be a generic deployment model:

~~~text
Application
Repository
Commit
Deployment
Domain
Service
Environment
Container/Image
~~~

Then vendor adapters can populate that model.

---

# 26. Security Backtesting — The Core Product Differentiator

This should become one of the most important parts of Magic_Security.

Every completed scan creates an immutable **scan snapshot**.

A snapshot contains:

- target identity;
- target version/commit if known;
- scan profile;
- timestamp;
- attack-surface fingerprint;
- coverage state;
- normalized findings;
- evidence fingerprints;
- environment metadata;
- scanner version.

The next scan is compared with a baseline.

## Finding States

~~~text
NEW
UNCHANGED
IMPROVED
WORSENED
RESOLVED
REINTRODUCED
UNKNOWN
~~~

## Example

~~~text
Scan #41
  /api/orders/{id}
  BOLA: not present

Deploy commit abc123

Scan #42
  /api/orders/{id}
  BOLA: VERIFIED

Result:
  NEW HIGH SECURITY REGRESSION
~~~

This is much more actionable than a static report.

---

# 27. Attack Surface Diffing

Backtesting should compare more than vulnerabilities.

Detect:

- new routes;
- removed routes;
- new methods;
- new parameters;
- endpoints becoming public;
- endpoints becoming authenticated;
- changed response fingerprints;
- new JS assets;
- new source maps;
- new WebSockets;
- new admin paths;
- new public artifacts.

Example:

~~~text
+ POST /api/admin/import
+ parameter: source_url
+ anonymous status: 200

No vulnerability is proven yet,
but the security-relevant attack surface expanded.
~~~

That should be visible immediately.

---

# 28. Coverage Diffing

A clean scan is meaningless if the scanner tested less than before.

Therefore we must also compare scan coverage.

Example:

~~~text
Previous:
  Browser: enabled
  Auth contexts: 2
  IDOR tests: 47

Current:
  Browser: disabled
  Auth contexts: 0
  IDOR tests: 0

Result:
  Scan cannot be considered equivalent to baseline.
~~~

A CI gate must never say “secure” simply because important tests did not run.

---

# 29. Finding Identity and Deduplication

A stable finding fingerprint should be based on security meaning, not raw response text.

Possible fingerprint inputs:

~~~text
target
category
check_id
normalized endpoint
HTTP method
parameter/location
authorization relationship
proof type
~~~

Evidence itself may change without creating a brand-new logical finding.

This is required for reliable regression tracking.

---

# 30. Severity vs Confidence

Severity and confidence must remain independent.

Example:

~~~text
Severity: HIGH
Confidence: LOW
~~~

may mean a dangerous-looking candidate without strong proof.

Whereas:

~~~text
Severity: HIGH
Confidence: VERIFIED
~~~

means the scanner reproduced the security failure.

Recommended confidence model:

- Candidate;
- Likely;
- Strong;
- Verified.

Recommended finding kinds:

- Vulnerability;
- Exposure;
- Hardening;
- Observation.

---

# 31. Risk Scoring

Do not rely on severity alone.

A future score may combine:

~~~text
Risk =
  Technical Impact
× Exploitability
× Reachability
× Authentication Requirement
× Data Sensitivity
× Confidence
× Regression Weight
~~~

A newly introduced verified issue should rank above an old hardening warning.

Business-critical targets may also receive a target criticality multiplier.

---

# 32. Evidence Model

Every verification pack should emit a normalized evidence object.

Conceptually:

~~~json
{
  "check_id": "authz.bola.read",
  "finding_kind": "Vulnerability",
  "severity": "HIGH",
  "confidence": "Verified",
  "endpoint": "/api/orders/{id}",
  "method": "GET",
  "proof": {
    "baseline": "user_b_cannot_own_resource",
    "mutation": "user_b_requests_user_a_resource",
    "result": "cross_account_resource_returned"
  },
  "sensitive_values_stored": false
}
~~~

The actual report should remain redacted.

---

# 33. Target Ownership and Authorization Model

For the local MVP, authentication/ownership of scanner users is intentionally unnecessary.

The operator controls the scanner locally.

Later, before remote multi-user scanning becomes a product feature, targets should have an explicit authorization state.

Potential verification mechanisms:

- DNS TXT challenge;
- well-known challenge file;
- repository/deployment connection;
- manual trusted-admin registration;
- CI-issued target registration.

Target states:

~~~text
UNVERIFIED
VERIFIED
SUSPENDED
EXPIRED
~~~

Remote active testing should require a verified target or an explicit trusted-local override.

This separates the scanner's security model from the security model of the scanned site.

---

# 34. Scan Scope

Every scan should produce an explicit immutable scope.

Example:

~~~yaml
target: https://example.com

scope:
  allowed_hosts:
    - example.com
    - api.example.com

  denied_paths:
    - /billing/live-charge
    - /admin/delete-all

limits:
  max_pages: 500
  max_requests: 5000
  concurrency: 8
  rate_per_second: 5

modes:
  passive: true
  active: true
  browser: true
  authenticated: true
  workflows: false
~~~

The scanner must not silently expand beyond scope.

---

# 35. Workflow Configuration

Security workflows should eventually be declarative.

Example:

~~~yaml
workflows:
  create_note:
    context: user_a

    create:
      method: POST
      path: /api/notes
      body:
        title: magic-security-canary
        body: safe-test-data

    extract:
      resource_id: $.id

    read:
      method: GET
      path: /api/notes/{resource_id}

    cleanup:
      method: DELETE
      path: /api/notes/{resource_id}
~~~

Then authorization tests can safely ask:

> Can user B read user A's disposable note?

This is dramatically safer and more reliable than guessing production behavior.

---

# 36. Scan Storage

The first implementation can remain filesystem-based.

Later storage should be split into:

## Relational Metadata

PostgreSQL:

- targets;
- scans;
- findings;
- finding_instances;
- coverage;
- attack_surface_nodes;
- attack_surface_edges;
- workflows;
- repositories;
- deployments.

## Large Evidence

Object storage:

- screenshots;
- bounded response artifacts;
- generated HTML reports.

Sensitive data retention should be intentionally minimized.

---

# 37. CLI, API, and UI

## Stage 1 — CLI

Keep CLI as the primary interface while the scanner is evolving quickly.

## Stage 2 — Local API

Add a small FastAPI control plane:

~~~text
POST /targets
POST /scans
GET  /scans/{id}
GET  /scans/{id}/findings
GET  /scans/{id}/diff
~~~

The scan engine should remain independent of the API layer.

## Stage 3 — Dashboard

Dashboard should focus on decisions, not vanity metrics.

Main screens:

- Targets;
- Latest Security Status;
- Regressions;
- Findings;
- Attack Surface;
- Coverage;
- Scan History;
- Baseline Diff;
- Workflow Configuration.

The first dashboard does not need complex multi-user RBAC.

---

# 38. Reporting

We should support four report formats.

## JSON

Machine-readable canonical format.

## Terminal

Developer-friendly summary.

## HTML

Human-readable standalone report.

## CI Summary

Small regression-focused output.

Example:

~~~text
Magic_Security: FAILED

New verified regressions:
  HIGH  BOLA       GET /api/orders/{id}
  MED   DOM XSS    /search

New exposures:
  LOW   source map /_next/static/chunks/app.js.map

Resolved:
  HIGH  unsafe credentialed CORS

Coverage:
  browser       equivalent
  authenticated equivalent
  authorization equivalent
~~~

---

# 39. CI/CD Integration

The end goal:

~~~text
Pull Request
     ↓
Build disposable preview environment
     ↓
Run Magic_Security
     ↓
Compare with main-branch baseline
     ↓
Post regression summary
     ↓
Pass / Fail security gate
~~~

CI should fail on policy, not simply on any finding.

Example policy:

~~~yaml
fail_on:
  new_verified:
    - critical
    - high

warn_on:
  new_verified:
    - medium

ignore_existing: true

require_coverage:
  browser: true
  authenticated_contexts: 2
~~~

This makes the scanner practical for active development.

---

# 40. Test Strategy for Magic_Security Itself

A security scanner that is not tested can create dangerous false confidence.

We need several test layers.

## 40.1 Unit Tests

For:

- parsing;
- normalization;
- classifiers;
- fingerprints;
- scoring;
- redaction;
- scope logic.

## 40.2 Synthetic Vulnerable Application

Maintain intentionally vulnerable demo routes.

Every supported verified check should have:

- vulnerable fixture;
- safe fixture;
- expected evidence;
- false-positive regression test.

## 40.3 End-to-End Scan Tests

Run complete scanner profiles against the synthetic app.

## 40.4 False-Positive Regression Suite

Whenever a false positive is discovered on a real application, create a sanitized regression fixture.

## 40.5 False-Negative Regression Suite

Whenever the scanner misses a bug it should have detected, create a minimal vulnerable fixture and preserve it forever.

This is how scanner quality compounds over time.

---

# 41. Scanner Quality Metrics

Useful engineering metrics:

- verified true-positive rate;
- false-positive rate;
- false-negative regression count;
- unique endpoint discovery;
- browser-added endpoint discovery;
- auth-only endpoint discovery;
- average scan duration;
- average requests per endpoint;
- percentage of findings with verified proof;
- percentage of coverage categories actually exercised;
- number of security regressions caught before production.

Avoid vanity metrics such as “number of checks” unless they correspond to meaningful coverage.

---

# 42. Performance Strategy

Scanning can become expensive quickly.

Future optimization:

- response fingerprints;
- request caching;
- endpoint normalization;
- semantic deduplication;
- per-pack prerequisites;
- changed-surface rescanning;
- historical attack-surface reuse;
- bounded concurrency;
- adaptive rate limits.

Example:

If 300 URLs normalize to the same endpoint pattern and response class, the scanner should avoid blindly repeating every expensive probe.

---

# 43. Safety Controller

Before every active request the engine should eventually evaluate:

~~~text
Is host in scope?
Is method allowed?
Is this check enabled?
Does this pack require workflow authorization?
Is target verified?
Is request budget available?
Is concurrency budget available?
Could this action mutate state?
Could it trigger external interaction?
Could it retrieve large/sensitive content?
~~~

This logic should be centralized instead of reimplemented by every security pack.

---

# 44. Redaction Layer

No pack should be responsible for inventing its own secret-handling policy.

A centralized redaction layer should handle:

- authorization headers;
- cookies;
- tokens;
- password-like fields;
- API keys;
- PII-like values;
- reset tokens;
- OTP values;
- query-string secrets.

Evidence objects should preferably reference redacted values by fingerprint.

---

# 45. Planned Internal Package Structure

The exact names may evolve, but the architecture should move toward:

~~~text
magic_security/
├── cli/
├── engine/
│   ├── orchestrator.py
│   ├── scope.py
│   ├── budgets.py
│   └── scan_context.py
│
├── discovery/
│   ├── http.py
│   ├── browser.py
│   ├── javascript.py
│   ├── openapi.py
│   ├── graphql.py
│   └── indexes.py
│
├── surface/
│   ├── models.py
│   ├── normalize.py
│   ├── graph.py
│   └── fingerprints.py
│
├── packs/
│   ├── browser/
│   ├── auth/
│   ├── authorization/
│   ├── injection/
│   ├── api/
│   ├── server/
│   ├── websocket/
│   ├── upload/
│   ├── workflow/
│   └── exposure/
│
├── evidence/
│   ├── models.py
│   ├── redact.py
│   ├── dedupe.py
│   └── confidence.py
│
├── backtesting/
│   ├── snapshot.py
│   ├── baseline.py
│   ├── diff.py
│   └── policy.py
│
├── repo_analysis/
├── infrastructure/
├── reporting/
└── integrations/
~~~

We should refactor toward this gradually, not rewrite v1.0 all at once.

---

# 46. Roadmap

The roadmap is organized around large capability milestones.

---

## Phase 0 — Current Local Black-Box Foundation

**Status: substantially implemented**

Goal:

> Build a trustworthy local external scanner before adding product infrastructure.

Includes:

- HTTP discovery;
- browser discovery;
- endpoint normalization;
- passive checks;
- safe active checks;
- browser verification;
- authenticated contexts;
- IDOR read verification;
- CORS;
- cache;
- GraphQL;
- session posture;
- server-side verification;
- sensitive surface discovery;
- coverage registry;
- evidence-driven findings;
- JSON reporting;
- test suite.

Exit criteria:

- deterministic local runs;
- no uncontrolled active behavior;
- useful coverage on the vulnerable demo app;
- low-noise reports;
- no secret values serialized.

---

## Phase 1 — Scanner Core Hardening

Goal:

> Turn the growing collection of checks into a stable scanning engine.

Work:

- central ScanContext;
- central scope enforcement;
- request budgets;
- concurrency budgets;
- central redaction;
- standardized check interface;
- standardized evidence schema;
- stable check IDs;
- confidence model;
- stable finding fingerprints;
- better cancellation/error isolation;
- pack-level metrics;
- improved structured logs.

Exit criteria:

- every active pack goes through the safety controller;
- every finding has a stable identity;
- every check declares prerequisites and proof rules;
- scanner failure in one pack does not corrupt the whole scan.

---

## Phase 2 — Security Backtesting Engine

**This is the next major product milestone.**

Goal:

> Compare security state over time.

Work:

- scan snapshot schema;
- filesystem scan history first;
- stable finding fingerprints;
- attack-surface fingerprints;
- baseline selection;
- finding diff;
- attack-surface diff;
- coverage diff;
- NEW / RESOLVED / REINTRODUCED states;
- regression-focused terminal report;
- policy evaluation.

Initial CLI idea:

~~~bash
magic-security scan http://127.0.0.1:8000 --name my-app
magic-security baseline set my-app latest
magic-security scan http://127.0.0.1:8000 --compare-baseline
magic-security diff my-app <scan-a> <scan-b>
~~~

Exit criteria:

- a deliberately introduced vulnerability is reported as NEW;
- fixing it produces RESOLVED;
- reintroducing it produces REINTRODUCED;
- scan coverage differences are visible;
- attack-surface changes are visible.

---

## Phase 3 — Workflow Engine

Goal:

> Safely test security classes that generic scanners cannot verify.

Work:

- declarative workflow format;
- variable extraction;
- disposable resource lifecycle;
- cleanup;
- multi-user workflow execution;
- workflow safety classification.

First workflows:

- create/read/delete resource;
- stored-XSS write/read;
- state-changing authorization;
- CSRF disposable action;
- upload/retrieve/delete;
- login/logout/session rotation.

Exit criteria:

- no generic destructive guessing;
- every mutation is declared;
- workflows clean up after themselves;
- state-changing authorization can be verified safely.

---

## Phase 4 — Repository-Aware Mode

Goal:

> Combine runtime truth with source context.

Start with the stacks we actually use most often.

Priority candidates:

1. Next.js / React;
2. Laravel / PHP;
3. Python / FastAPI;
4. Node/Express.

Capabilities:

- route extraction;
- endpoint-to-source mapping;
- auth middleware mapping;
- secret scanning;
- dangerous config scanning;
- dependency manifests;
- Dockerfile checks;
- CI workflow checks.

Exit criteria:

- runtime endpoint maps to likely source implementation;
- source-only findings clearly marked as source findings;
- black-box findings can include source location hints;
- repo access meaningfully reduces blind spots.

---

## Phase 5 — Remote Authorized Target Mode

Goal:

> Run the scanner against our owned staging/production sites with explicit safety controls.

Work:

- target registry;
- verified target state;
- domain allowlist;
- host/subdomain scope;
- request budgets;
- production-safe profile;
- environment classification;
- test account configuration;
- encrypted local secret storage.

We should enable remote scanning gradually.

Initial remote profile should exclude high-risk workflow mutations.

Exit criteria:

- scanner cannot follow out-of-scope hosts;
- active packs respect production-safe budgets;
- target authorization is explicit;
- credentials never appear in reports.

---

## Phase 6 — API + Local Dashboard

Goal:

> Make multi-target security status easy to inspect.

Work:

- FastAPI control plane;
- PostgreSQL;
- scan queue;
- scan status;
- targets;
- findings;
- baselines;
- regressions;
- HTML report;
- simple dashboard.

No complex SaaS authentication is required yet if this remains locally operated.

Exit criteria:

- register multiple owned sites;
- run scan;
- view history;
- compare baseline;
- inspect new regressions.

---

## Phase 7 — CI/CD Security Regression Gate

Goal:

> Catch new security problems before merge/deployment.

Work:

- GitHub Actions integration;
- preview environment scanning;
- baseline from main;
- regression policy;
- PR summary;
- artifact reports.

Exit criteria:

- intentional new high-severity verified issue blocks CI;
- existing debt does not necessarily block CI;
- weaker coverage cannot silently pass.

---

## Phase 8 — Infrastructure-Aware Mode

Goal:

> Correlate application findings with deployment configuration.

Start only with platforms we actively use.

Possible first adapters:

- Railway;
- Docker;
- Nginx;
- GitHub Actions.

Later:

- Cloudflare;
- AWS;
- ArvanCloud;
- Cloudways.

---

## Phase 9 — Intelligent Security Reasoning

Goal:

> Use an LLM as a reasoning assistant over structured evidence, not as the source of truth.

Appropriate LLM tasks:

- explain findings;
- summarize attack-surface changes;
- infer likely developer remediation;
- correlate related findings;
- propose workflow tests;
- explain why coverage is incomplete;
- prioritize regressions.

The LLM should not be allowed to turn an unverified guess into a “verified vulnerability.”

Deterministic evidence remains authoritative.

---

# 47. Recommended Immediate Next Steps

Given the current v1.0 state, the next work should **not** be “add random checks forever.”

The strongest next sequence is:

## Step A — Stabilize the Scanner Contract

Introduce:

- stable check IDs;
- confidence;
- centralized evidence;
- centralized redaction;
- centralized scope/safety.

## Step B — Build Snapshot + Diff

This creates the actual backtesting product.

Implement:

- ScanSnapshot;
- finding fingerprint;
- surface fingerprint;
- baseline;
- diff.

## Step C — Improve Findings UX

Add:

- concise terminal summary;
- HTML report;
- remediation field;
- reproduction/evidence section;
- coverage section.

## Step D — Workflow Engine

Start with disposable CRUD resources and stored XSS / authorization.

## Step E — Remote Owned-Site Mode

Only after safety/scope and snapshots are stable.

## Step F — Repo-Aware Mode

Prioritize Next.js and Laravel because they are highly relevant to our existing applications.

---

# 48. Definition of “Good Enough to Use on Our Sites”

Before treating Magic_Security as a real security backtester for owned sites, it should meet these conditions:

- scanner scope is explicit;
- request budget is bounded;
- remote hosts outside scope are blocked;
- credentials are redacted;
- findings have stable IDs;
- verified vulnerabilities contain reproducible evidence;
- baseline comparison works;
- coverage comparison works;
- browser mode is stable;
- authenticated contexts are stable;
- false positives from demo/real-world testing are tracked;
- failures are visible instead of silently ignored;
- production-safe mode exists;
- reports distinguish “not found” from “not tested.”

---

# 49. Definition of “Professional External Coverage”

Magic_Security should not claim professional coverage because it has many checks.

It should claim professional external coverage only when it reliably performs the following loop:

~~~text
Discover deeply
→ understand context
→ generate safe test hypothesis
→ establish baseline
→ mutate one security assumption
→ verify meaningful difference
→ retain minimal evidence
→ classify correctly
→ deduplicate
→ report coverage honestly
→ reproduce in future scans
~~~

That is the behavior we want.

---

# 50. Long-Term Success Condition

Magic_Security succeeds when our workflow becomes:

~~~text
Build quickly
     ↓
Deploy preview/staging
     ↓
Magic_Security backtest
     ↓
Review only meaningful regressions
     ↓
Fix
     ↓
Deploy
     ↓
Continuous scheduled regression scans
~~~

The target experience is not:

> “Here are 847 warnings.”

It is:

> “Your latest deployment introduced two new externally verified security regressions. One previously known exposure was resolved. Authorization coverage remained equivalent to baseline. No other verified regressions were observed.”

That is the standard this project should aim for.

---

# 51. Final Product Statement

**Magic_Security is an evidence-driven security backtesting platform for modern web applications.**

It begins as a local-first black-box scanner.

It evolves into a system that combines:

- external behavior;
- browser behavior;
- authenticated user behavior;
- workflow-based testing;
- repository context;
- deployment context;
- historical baselines.

Its purpose is not to claim that software is “secure.”

Its purpose is to continuously answer a more defensible question:

> **What security behavior can we verify, what changed, what regressed, and what remains untested?**

That principle should remain the architectural center of the project.
