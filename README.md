# Magic_Security

Local-first black-box web security scanner focused on **verified evidence, not checklist noise**.

## v0.7 — External Security Verification Pack

Magic_Security now combines browser-visible attack-surface discovery, authenticated authorization testing, and a broader external verification pack.

```
HTTP / JS / OpenAPI Discovery
        ↓
Anonymous + Authenticated Browser Discovery
        ↓
Attack Surface Normalization
        ↓
External Verification Pack
        ├─ Reflected HTML injection
        ├─ Browser-verified reflected XSS
        ├─ GraphQL introspection / debug exposure
        ├─ Client JS + source-map secret analysis
        ├─ Internal topology leakage
        ├─ CORS verification
        ├─ Protected credentialed CORS impact
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

Results are separated into:

- **Vulnerability** — reproduced security failure
- **Exposure** — verified dangerous public/browser-visible surface
- **Hardening** — defensive configuration problem
- **Observation / posture** — tested behavior that is not strong enough to call a vulnerability

That last category matters: for example, not observing a rate limit after a few requests is recorded as behavior, not falsely promoted to “brute force vulnerability”.

---

## External Security Pack

### Reflected HTML injection

For discovered GET parameters, Magic_Security uses a random inert custom HTML element as a canary.

It reports a vulnerability only if the response parser confirms that the supplied value became actual markup.

### Browser-verified reflected XSS

When `--browser` is enabled, Playwright can perform a stronger proof.

The XSS canary:

- only changes a DOM attribute
- performs no network callback
- reads no cookies
- reads no local/session storage
- sends no application data anywhere

If the DOM marker is executed, Magic_Security reports:

```
Reflected XSS execution verified
```

### GraphQL

GraphQL endpoints are tested with a minimal anonymous introspection query.

The scanner records:

- endpoint status
- anonymous introspection availability
- detailed debug/error extensions

Introspection is classified as an exposure, not automatically a vulnerability.

### Client JavaScript and source maps

Browser-downloadable JS and `sourcesContent` are inspected for:

- secret/password/token/API-key style assignments
- JWT-like token shapes
- private-key material
- private/internal network URLs

Values are redacted and never written into reports.

### Protected CORS impact

With test accounts, Magic_Security revisits endpoints already proven to be protected.

If an authenticated HTTP 200 response:

- reflects the scanner-controlled untrusted Origin
- enables `Access-Control-Allow-Credentials: true`

the report records a high-confidence protected CORS exposure.

### Authenticated cache behavior

For protected endpoints whose responses differ between users, Magic_Security inspects caching policy.

Explicit shared-cache directives such as:

```
Cache-Control: public
s-maxage=...
```

on user-specific authenticated responses are reported as exposures.

### Rate-limit behavior

A small bounded GET-only request series records:

- statuses
- 429 behavior
- Retry-After
- RateLimit / X-RateLimit headers

No vulnerability is declared simply because throttling was not seen in a tiny sample.

---

## Auth Security Suite

The existing authenticated suite remains integrated:

- multiple test contexts
- optional role metadata
- authenticated browser discovery
- anonymous-vs-auth boundary matrix
- user-specific response detection
- ownership-ID discovery from the app itself
- same-role pairwise authorization testing
- path-based IDOR/BOLA
- query-based IDOR/BOLA
- weak session-cookie analysis
- CSRF posture mapping

Magic_Security does not brute-force object IDs. It only reuses IDs discovered from each test account's own authenticated responses.

---

## Coverage reporting

The JSON report now includes two explicit coverage sections.

### Auth Security coverage

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

### External Security coverage

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

This prevents “40+ categories” marketing from pretending that every class was fully tested.

---

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

The demo contains fake-only vulnerabilities/exposures including:

- reflected XSS
- exposed fake client secret
- internal network URL leakage
- source maps
- GraphQL introspection
- Open Redirect
- unsafe CORS
- credentialed CORS on a protected endpoint
- user-specific response marked publicly cacheable
- exposed fake `.env`
- exposed fake Git metadata
- unauthenticated fake personal data
- path IDOR/BOLA
- query IDOR/BOLA
- weak session-cookie attributes
- CSRF posture candidate
- authenticated-only browser routes/APIs

---

## Safety defaults

The current MVP is intentionally constrained:

- localhost / loopback targets only
- browser cross-origin requests blocked
- no object-ID brute force
- no arbitrary button clicking
- no automatic form submission
- authorization exploitation limited to GET
- bounded rate-behavior requests
- XSS proof uses a DOM-only canary
- no secret values written into reports

---

## Architecture

```
magic_security/
├── active.py
├── auth.py
├── behavior_security.py
├── browser.py
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

## Tests

```bash
pytest
```

GitHub Actions runs tests on pushes and pull requests.

## What is still outside pure black-box/browser coverage?

A professional external scanner can get very far, but it cannot reliably prove every security class from the user side alone.

Examples that later need more context or explicitly configured destructive-safe workflows:

- complex business-logic abuse
- race conditions / double-spend
- deep server-side SSRF confirmation
- arbitrary file-upload execution
- backend dependency vulnerabilities
- cloud/IAM mistakes invisible from the public app
- server-only secret leakage
- source-code-only authorization flaws
- state-changing CSRF proof
- state-changing BOLA proof

Those belong in later verification packs or repo/cloud integrations.

The principle stays the same:

**Report what we can prove, and explicitly show what we have not proven.**
