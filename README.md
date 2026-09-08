# Magic_Security

Local-first web security scanner focused on **verified evidence, not checklist noise**.

## v0.6 pipeline

```
HTTP / JS / OpenAPI Discovery
        ↓
Anonymous + Authenticated Browser Discovery
        ↓
Attack Surface Normalization
        ↓
Anonymous Response Classification
        ↓
Authorization Matrix
        ↓
Ownership Discovery
        ↓
Pairwise IDOR / BOLA Verification
   path + query parameters
        ↓
Session Cookie Analysis
        ↓
CSRF Posture Mapping
        ↓
Fingerprint + Deduplicate
        ↓
Evidence Report
```

The current project is still intentionally local-first. There is no SaaS UI, billing, database, queue, or public-target scanning yet.

## Core rule

**No proof -> no vulnerability.**

Magic_Security separates:

- **Vulnerability** — reproduced security failure
- **Exposure** — dangerous observable surface
- **Hardening** — defensive configuration
- **Posture/Candidate** — needs stronger verification and is not promoted to a vulnerability

---

# Auth Security Suite v1

The main v0.6 milestone is a larger authenticated-security engine.

## 1. Multi-context authorization matrix

Auth contexts can include role metadata plus test headers/cookies:

```json
{
  "contexts": [
    {
      "name": "user_a",
      "role": "customer",
      "headers": {},
      "cookies": {
        "demo_session": "A"
      }
    },
    {
      "name": "user_b",
      "role": "customer",
      "headers": {},
      "cookies": {
        "demo_session": "B"
      }
    },
    {
      "name": "admin",
      "role": "admin",
      "headers": {},
      "cookies": {
        "demo_session": "ADMIN"
      }
    }
  ]
}
```

For concrete GET endpoints the scanner compares:

```
Anonymous
User A
User B
Admin
...
```

and classifies boundaries such as:

- `protected`
- `public_or_unprotected`
- `denied_for_all`
- `inconsistent`
- `unknown`

It also tracks when authenticated contexts receive different response fingerprints, which helps locate user-specific APIs.

## 2. Authenticated browser discovery

With both `--browser` and `--auth-contexts`, Playwright creates isolated browser contexts for every supplied test identity.

It discovers:

- login-only routes
- runtime links/forms
- authenticated XHR/fetch calls
- query/body parameter names
- context-specific APIs

Provenance is preserved:

```
browser:user_a:network
browser:user_b:network
browser:admin:network
```

Credential values are never serialized.

## 3. Ownership discovery

Magic_Security learns object identifiers only from authenticated application responses.

Examples:

- `account_id`
- `user_id`
- `order_id`
- `invoice_id`
- `project_id`
- other `*_id` fields

Ownership learning prefers endpoints that are both:

- protected
- user-specific

The report stores only:

- context name
- identifier field name
- number of discovered values
- source endpoints

Raw object identifiers are not written to the report.

## 4. Pairwise IDOR / BOLA verification

Object authorization is tested across same-role contexts by default.

That matters because:

```
customer -> customer
```

is a useful horizontal authorization test, while:

```
admin -> customer
```

may be intentionally allowed.

If role metadata is absent, contexts remain pairwise-testable.

### Path parameter verification

Example:

```
GET /api/accounts/{account_id}
```

The scanner:

1. learns User A's own `account_id`
2. learns User B's own `account_id`
3. establishes owner responses
4. replays User A's object using User B
5. compares the returned JSON with the owner's baseline

A vulnerability is reported only if cross-account HTTP 200 returns the same object.

### Query parameter verification

v0.6 also covers ID-style query parameters:

```
GET /api/account-detail?account_id=...
```

So IDOR coverage is no longer limited to path templates.

### No brute force

The scanner never guesses sequential IDs.

It only reuses identifiers already observed from the supplied test accounts' own authenticated responses.

## 5. Session cookie analysis

Authenticated GET responses are inspected for session-like `Set-Cookie` headers.

The scanner records only:

- cookie name
- source endpoint
- context name
- `Secure`
- `HttpOnly`
- `SameSite`

Cookie values are discarded.

Session-like cookies missing protections become **Hardening** findings rather than fake exploit claims.

## 6. CSRF posture mapping

State-changing endpoints are mapped:

- POST
- PUT
- PATCH
- DELETE

Magic_Security looks at:

- authentication style
- discovered parameter names
- CSRF/XSRF token signals

Posture examples:

- `header_authenticated`
- `token_signal_present`
- `cookie_authenticated_needs_verification`
- `auth_mechanism_unknown`

Important: CSRF posture is **not automatically a vulnerability**.

The scanner does not issue unsafe state-changing exploit requests just to create a dramatic finding.

## 7. Auth Security Coverage

The report now includes a dedicated coverage section:

```
Auth compared endpoints
Protected endpoints
User-specific endpoints
Ownership signals
Pairwise IDOR tests
Verified IDOR/BOLA
State-changing endpoints
CSRF candidates needing verification
Session cookies observed
Weak session-cookie observations
```

This makes it clear what was actually tested instead of implying universal coverage.

---

# Existing coverage

## Passive

- security headers
- cookie flags
- directory listing
- Swagger/OpenAPI exposure
- debug/stack traces
- exposed `.env`
- exposed `.git/HEAD`
- source-map exposure
- JS/API discovery
- secret redaction

## Safe-active

- CORS arbitrary-origin reflection
- credentialed CORS reflection
- Open Redirect
- anonymous endpoint classification
- unauthenticated sensitive-looking JSON exposure

## Authenticated read-only

- auth boundary mapping
- authenticated browser discovery
- user-specific response detection
- ownership discovery
- path IDOR/BOLA
- query IDOR/BOLA
- same-role pairwise authorization testing
- session cookie analysis
- CSRF posture mapping

---

# Install

Base scanner:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Browser mode:

```bash
pip install -e ".[dev,browser]"
playwright install chromium
```

---

# Run the full local demo

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

The demo uses fake identities, fake cookies, and fake data only.

It intentionally contains:

- exposed fake `.env`
- fake Git metadata
- source map exposure
- directory listing
- OpenAPI exposure
- unsafe CORS
- Open Redirect
- unauthenticated fake personal-data JSON
- authenticated-only dashboard/API discovery
- weak session-cookie attributes
- path-based cross-account object access
- query-based cross-account object access
- cookie-authenticated state-changing endpoint with no obvious CSRF token signal

The scanner does **not** submit the state-changing CSRF candidate.

---

# Report privacy

The JSON report does not serialize:

- Authorization values
- cookie values
- access tokens
- authenticated response bodies
- raw object identifiers used in IDOR verification

It can store:

- context names
- roles indirectly through local configuration only
- endpoint URLs
- parameter names
- status codes
- response/finding fingerprints
- cookie names and attributes
- ownership counts
- verification results

---

# Safety defaults

The current MVP:

- only scans localhost/loopback
- blocks browser cross-origin requests
- does not brute-force object IDs
- does not submit browser forms
- does not click arbitrary actions
- limits authorization exploitation to GET requests
- does not perform state-changing IDOR testing
- does not promote CSRF posture into a vulnerability without proof

---

# Architecture

```
magic_security/
├── active.py
├── auth.py
├── browser.py
├── classifier.py
├── coverage.py
├── crawler.py
├── csrf.py
├── discovery.py
├── engine.py
├── fingerprints.py
├── idor.py
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

GitHub Actions runs the suite on pushes and pull requests.

## Next large milestone

The next milestone should be **Security Verification Pack v2**, not another tiny feature:

- safe reflected XSS verification
- stronger CORS impact verification
- source-map secret analysis
- GraphQL attack-surface analysis
- rate-limit behavior classification
- session-fixation / session-rotation checks
- safe CSRF proof with explicitly configured disposable test actions
- richer authorization relationship graphs

The product principle remains:

**We report what we can prove.**
