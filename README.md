# Magic_Security

Local-first black-box web security scanner focused on **verified evidence, not checklist noise**.

## v0.8 — Professional Browser + External Security Pack

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

## Safety defaults

The current scanner remains intentionally constrained:

- localhost / loopback only
- browser cross-origin HTTP requests blocked
- no object-ID brute force
- no arbitrary button clicking
- no automatic form submission
- authorization exploitation limited to GET
- bounded rate-behavior requests
- reflected/DOM XSS proof uses DOM-only canaries
- no secret values written into reports

## What black-box testing still cannot reliably prove

A strong external scanner can cover a lot, but not literally every security flaw can be proven from the user side alone.

Examples that need later verification packs or repo/cloud context:

- complex business-logic abuse
- race conditions / double-spend
- deep SSRF confirmation
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
├── probes.py
├── reporting.py
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
