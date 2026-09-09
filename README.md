# Magic_Security

Local-first black-box web security scanner focused on **verified evidence, not checklist noise**.

> 📘 **Project direction:** See the [Master Product Plan, Architecture, and Roadmap](docs/MASTER_PLAN.md) for the complete Security Backtesting vision, milestones, safety model, and future architecture.

## v1.1 — Security Backtesting Foundation

v1.1 adds the first historical regression layer on top of the evidence-driven scanner.

A scan can now be saved as a compact security snapshot:

```bash
magic-security http://127.0.0.1:8000 \
  --browser --active \
  --snapshot reports/baseline.snapshot.json
```

A later scan can be compared with that baseline:

```bash
magic-security http://127.0.0.1:8000 \
  --browser --active \
  --baseline reports/baseline.snapshot.json \
  --snapshot reports/current.snapshot.json
```

The backtest reports:

- `NEW`
- `REINTRODUCED`
- `WORSENED`
- `IMPROVED`
- `RESOLVED`
- `UNCHANGED`
- attack-surface additions/removals
- coverage changes and mode equivalence

Finding identity now uses stable `check_id` values and versioned fingerprints instead of depending on report wording. Dynamic resource IDs in attack-surface URLs are normalized to reduce false diffs between scans.

This is the foundation for future CI regression gates and multi-scan baselines described in the master plan.

## v1.0 — Professional User-Side Coverage

v1.0 expands the scanner toward the surface a professional external pentester can observe from the application/user side without source, cloud, or host access.

New coverage:

- `robots.txt` and `sitemap.xml` attack-surface discovery
- hidden/disallowed route ingestion into normalized endpoints
- public SVN/Hg/DS_Store metadata signatures
- exposed package/composer manifests
- public backup ZIP and SQL-dump signatures
- Apache status / phpinfo / Go debug vars / Java WEB-INF probes
- Spring Actuator environment and heap-dump exposure checks
- public config JSON with secret-like key detection
- populated token/session/password/OTP/reset-token parameters in URLs
- PII/payment-like values in URLs
- sensitive fields submitted through GET forms
- HTTPS mixed-content and insecure form/resource references
- `Origin: null` CORS acceptance
- JSONP arbitrary callback wrapping
- dedicated **User-Side Security Coverage** counters
- more conservative 42-category coverage labels

Large responses such as heap dumps are **not downloaded**. Backup/config probes read only a bounded response prefix or use HEAD where possible. Secret values and sensitive URL values are never written into reports.

The coverage registry is intentionally stricter in v1.0: authentication, authorization, SQL, XSS, GraphQL, CORS, and similar broad classes are marked **Partially Tested** rather than pretending a black-box scanner can exhaustively prove every variant.

A professional external scanner can cover a large portion of observable web risk, but literally every bug is impossible from the user side alone. Business invariants, destructive workflows, race conditions, payment abuse, stored-upload chains, MFA/reset takeover, cloud/IAM, supply-chain, and source-only flaws still require explicit workflows or repo/infrastructure context.

## v0.9 — Black-Box Verification Pack

Magic_Security now combines:

```
HTTP / JS / OpenAPI Discovery
        ↓
Anonymous + Authenticated Browser Discovery
        ↓
Attack Surface Normalization
        ↓
Browser Security Pack
        ├─ Reflected XSS
        ├─ DOM XSS runtime verification
        ├─ Browser storage inspection
        ├─ Web Messaging / postMessage review
        ├─ Client-side redirect analysis
        ├─ WebSocket discovery
        └─ Clickjacking / CSP posture
        ↓
External Verification Pack
        ├─ HTML injection
        ├─ GraphQL introspection / debug exposure
        ├─ Client JS + source-map secret analysis
        ├─ Internal topology leakage
        ├─ CORS verification
        ├─ Protected credentialed CORS
        ├─ Authenticated cache behavior
        └─ Rate-limit behavior classification
        ↓
Auth Security Suite
        ├─ Anonymous/User/Role matrix
        ├─ Ownership discovery
        ├─ Path + query IDOR/BOLA
        ├─ Session cookie analysis
        └─ CSRF posture mapping
        ↓
Fingerprint + Deduplicate
        ↓
Evidence + Coverage Report
```

## Product rule

**No proof -> no vulnerability.**

Results remain separated into:

- **Vulnerability** — reproduced security failure
- **Exposure** — dangerous observable surface
- **Hardening** — defensive configuration problem
- **Observation / posture** — a signal that still needs stronger verification

## Browser Security Pack

### DOM-based XSS

Static JavaScript analysis looks for browser-controlled sources such as:

- `location.search`
- `location.hash`
- `document.URL`
- `document.referrer`
- `window.name`

and unsafe sinks such as:

- `innerHTML`
- `outerHTML`
- `insertAdjacentHTML`
- `document.write`
- `eval`
- `new Function`

When `--browser --active` is enabled, Magic_Security performs a stronger browser proof using a harmless fragment canary.

The canary only sets a DOM attribute. It does not read cookies, storage, or application data and it performs no callback.

A vulnerability is reported only when code execution is actually observed.

### Browser storage

Playwright inspects **storage key names only** from:

- `localStorage`
- `sessionStorage`

Security-relevant names such as token/auth/session/JWT/secret/password keys are surfaced.

Stored values are never read into the report.

### Web Messaging

Browser-delivered JavaScript is inspected for:

- `addEventListener("message", ...)`
- `onmessage = ...`
- obvious `event.origin` validation signals

A missing origin-validation signal is an **Exposure candidate**, not automatically a vulnerability.

### Client-side redirects

Magic_Security looks for browser-controlled URL sources flowing near:

- `location.href = ...`
- `location.assign(...)`
- `location.replace(...)`

These remain candidates until runtime control is proven.

### WebSockets

WebSocket endpoints are collected from:

- JavaScript references
- runtime Playwright WebSocket events

An HTTPS application referencing plaintext `ws://` is reported as an exposure.

Full WebSocket authorization / CSWSH verification is a later pack.

### Clickjacking and CSP

HTML pages are checked for anti-framing protection:

- `X-Frame-Options`
- CSP `frame-ancestors`

CSP policies using `'unsafe-inline'` or `'unsafe-eval'` are also surfaced as hardening weaknesses.

## Parameter + Protocol Verification

v0.9 adds another black-box layer for user-controlled inputs and HTTP behavior:

- database-error trigger detection using a harmless apostrophe probe
- server-side template evaluation verification using arithmetic-only `{{1337*7}}`
- CRLF / response-header injection verification with an inert response header
- duplicate-parameter / HTTP parameter pollution behavior mapping
- TRACE reflection detection
- OPTIONS / dangerous-method exposure
- Server / X-Powered-By fingerprint leakage

Important distinction:

- a triggered database error is reported as an **Exposure**, not falsely promoted to proven SQL injection
- SSTI is a **Vulnerability** only when the arithmetic expression is actually evaluated
- CRLF is a **Vulnerability** only when the controlled response header appears
- parameter-pollution differences remain observations until exploit impact is demonstrated

## 42-Category Coverage Registry

Every report now includes the original 42 security categories with an explicit status:

- `Fully Tested`
- `Partial`
- `Passive Only`
- `Requires Auth`
- `Requires Config`
- `Requires Repo Access`

This is intentionally honest. Black-box scanning cannot reliably prove every business-logic, cloud/IAM, supply-chain, file-upload, race-condition, or SSRF issue without extra configuration or source/infrastructure context.

## Server-Side Black-Box Verification Pack

v0.9 adds backend vulnerabilities that can be proven from the outside without source or host access.

### Database / authentication injection

Existing parameter testing keeps database-error responses as an **Exposure signal**, not automatic SQLi proof.

For discovered login/token POST endpoints, v0.9 also compares a synthetic invalid-login baseline against:

- SQL-style credential probes
- NoSQL operator-object probes

A critical authentication-bypass finding is created only when the baseline fails but the probe returns an authenticated success signal such as a session cookie/token/user response.

No real credentials are used.

### Path traversal / LFI

File/path-like GET parameters are tested with only known non-secret marker files:

- Unix hosts-file markers
- Windows win.ini markers

A vulnerability is reported only when the marker set appears after traversal and is absent from the baseline. File content is not stored in the report.

### SSRF callback verification

URL-like GET parameters can be verified against a scanner-owned HTTP listener bound only to:

```
127.0.0.1
```

Each probe uses a unique callback token. SSRF is verified only when that token is received.

Magic_Security does **not** probe:

- cloud metadata endpoints
- private network services
- public callback infrastructure
- arbitrary external hosts

### Host-header influence

HTML pages are compared with a controlled `Host` / `X-Forwarded-Host` marker.

If the attacker-controlled hostname appears only in the poisoned response or redirect location, the scanner reports concrete Host-header influence. It does not claim password-reset poisoning unless such a workflow is later configured and verified.

### POST login/token rate limiting

Rate behavior now includes bounded synthetic requests to discovered login/token POST endpoints, in addition to safe GET endpoints.

Only fake invalid credentials are sent, and the scanner stops early on HTTP 429.

### Server coverage

The report includes:

```
coverage.server_security
server_security.observations
```

with counters for:

- database error triggers
- SSTI arithmetic verification
- CRLF header injection
- path traversal / LFI
- loopback-callback SSRF
- SQL-style auth bypass
- NoSQL operator auth bypass
- Host-header response influence

Probe payloads, callback tokens, credentials, and file contents are not serialized.

## Existing external verification

v0.8 keeps the existing v0.7 pack:

- reflected HTML injection
- browser-verified reflected XSS
- GraphQL anonymous introspection
- GraphQL detailed error exposure
- frontend/source-map secret-like material
- internal/private network URL leakage
- Open Redirect
- CORS reflection
- protected credentialed CORS
- user-specific shared-cache exposure
- bounded rate-limit behavior classification
- unauthenticated sensitive-looking JSON exposure

## Auth Security Suite

Authenticated testing supports:

- multiple test contexts
- optional role metadata
- authenticated browser discovery
- anonymous-vs-auth boundary mapping
- user-specific response detection
- ownership-ID discovery from the app itself
- same-role pairwise authorization testing
- path IDOR/BOLA
- query IDOR/BOLA
- weak session-cookie analysis
- CSRF posture mapping

Magic_Security does not brute-force object IDs. It only reuses IDs learned from each test account's own authenticated responses.

## Coverage reporting

The JSON report exposes three explicit coverage sections:

### Browser Security

```
artifacts_scanned
dom_source_sink_candidates
dom_xss_verified
message_handlers
message_handlers_missing_origin
client_redirect_candidates
sensitive_storage_keys
websocket_endpoints
```

### External Security

```
injection_tests
html_injection_verified
xss_execution_verified
graphql_endpoints_tested
graphql_introspection_exposed
graphql_detailed_errors
client_artifacts_scanned
secret_like_artifacts
internal_topology_artifacts
protected_cors_tests
protected_cors_exposed
authenticated_cache_tests
risky_shared_cache
rate_limit_endpoints_tested
rate_limit_throttled
parameter_security_tests
database_error_triggers
ssti_verified
crlf_verified
parameter_pollution_observations
protocol_observations
```

### Auth Security

```
auth_compared_endpoints
protected_endpoints
user_specific_endpoints
ownership_signals
idor_pairwise_tests
idor_verified
state_changing_endpoints
csrf_needs_verification
session_cookies_observed
weak_session_cookie_observations
```

This prevents the scanner from pretending a security class was fully tested when it was only partially observable.

## Install

Base:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Browser support:

```bash
pip install -e ".[dev,browser]"
playwright install chromium
```

## Full local scan

Terminal 1:

```bash
python examples/vulnerable_app.py
```

Terminal 2:

```bash
magic-security http://127.0.0.1:8000 \
  --browser \
  --active \
  --auth-contexts examples/auth_contexts.example.json \
  --json reports/demo.json
```

The demo uses fake-only credentials and data. It intentionally contains examples for:

- reflected XSS
- DOM XSS
- frontend/source-map fake secrets
- internal URL leakage
- unsafe postMessage handling
- client-side redirect signal
- WebSocket discovery
- sensitive-looking browser storage
- GraphQL introspection
- Open Redirect
- unsafe CORS
- credentialed CORS on a protected endpoint
- risky authenticated shared caching
- exposed fake `.env`
- exposed fake Git metadata
- unauthenticated fake personal data
- path IDOR/BOLA
- query IDOR/BOLA
- weak session cookies
- CSRF posture candidate
- missing anti-clickjacking headers
- SSTI arithmetic evaluation
- database error triggering
- CRLF response-header injection
- TRACE reflection / method exposure

## Safety defaults

The current scanner remains intentionally constrained:

- localhost / loopback only
- browser cross-origin HTTP requests blocked
- no object-ID brute force
- no arbitrary button clicking
- no automatic form submission
- authorization exploitation limited to GET
- bounded rate-behavior requests, including synthetic login/token probes
- reflected/DOM XSS proof uses DOM-only canaries
- no secret values written into reports

## What black-box testing still cannot reliably prove

A strong external scanner can cover a lot, but not literally every security flaw can be proven from the user side alone.

Examples that need later verification packs or repo/cloud context:

- complex business-logic abuse
- race conditions / double-spend
- SSRF impact beyond the safe loopback callback (for example cloud metadata or internal-service access)
- file-upload-to-code-execution chains
- backend dependency vulnerabilities
- cloud/IAM mistakes invisible from the app
- server-only secrets
- source-code-only authorization flaws
- destructive state-changing CSRF/BOLA scenarios

Those will stay explicitly marked as untested or partially tested instead of being guessed.

## Architecture

```
magic_security/
├── active.py
├── auth.py
├── behavior_security.py
├── browser.py
├── browser_security.py
├── classifier.py
├── client_artifacts.py
├── coverage.py
├── crawler.py
├── csrf.py
├── discovery.py
├── engine.py
├── external_coverage.py
├── fingerprints.py
├── graphql_security.py
├── idor.py
├── injection.py
├── models.py
├── openapi.py
├── parameter_security.py
├── protocol_security.py
├── coverage_registry.py
├── probes.py
├── reporting.py
├── server_coverage.py
├── server_security.py
├── session_security.py
├── surface.py
└── checks/
```

## Test

```bash
pytest
```

GitHub Actions runs tests on pushes and pull requests.

The principle stays the same:

**Report what we can prove, and explicitly show what we have not proven.**
