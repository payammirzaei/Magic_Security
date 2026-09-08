# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## Current pipeline

```
URL
 -> HTTP / Browser / OpenAPI Discovery
 -> Normalize Attack Surface
 -> Anonymous Endpoint Classification
 -> Test-Account Auth Boundary Mapping
 -> Read-only IDOR / BOLA Verification
 -> Security Checks
 -> Safe-Active Verification
 -> Fingerprint + Deduplicate
 -> Evidence Report
```

The current milestone intentionally has no SaaS layer: no auth UI, billing, database, queue, or frontend.

## What it can do now

### Discovery

- same-origin HTTP crawl
- HTML links/forms/parameters
- frontend JavaScript API extraction
- OpenAPI / Swagger ingestion
- source-map discovery
- optional Playwright runtime discovery
- endpoint normalization across HTTP / JS / browser / OpenAPI sources

### Anonymous response classification

With `--active`, GET endpoints are requested without auth and classified as:

- `auth_required`
- `json`
- `html`
- `redirect`
- `not_found`
- `client_error`
- `server_error`
- `empty`
- `other`

The scanner can also verify sensitive-looking JSON fields exposed without authentication. Field **names** are reported; values are not stored.

## Test-account auth boundary mapping

Magic_Security can compare the same endpoint in three contexts:

```
Anonymous
User A
User B
```

The test contexts are provided through a local JSON file containing headers and/or cookies.

Example:

```json
{
  "contexts": [
    {
      "name": "user_a",
      "headers": {"X-Demo-User": "A"},
      "cookies": {}
    },
    {
      "name": "user_b",
      "headers": {"X-Demo-User": "B"},
      "cookies": {}
    }
  ]
}
```

A fake ready-to-use example lives at:

```
examples/auth_contexts.example.json
```

Credentials are local input only and are not written into scan reports.

## Verified read-only IDOR / BOLA

The first object-level authorization verifier is now implemented.

It does **not** brute-force IDs.

It works like this:

1. Use the first two explicit test-account contexts.
2. Request authenticated concrete GET endpoints.
3. Learn IDs that the application itself returns, such as:
   - `account_id`
   - `user_id`
   - `order_id`
   - `invoice_id`
4. Match those IDs to discovered path templates such as:

```
GET /api/accounts/{account_id}
```

5. Establish an owner baseline:
   - User A -> User A object
   - User B -> User B object
6. Cross-test:
   - User B -> User A object
   - User A -> User B object
7. Report a vulnerability only if the cross-account HTTP 200 JSON is identical to the owner's baseline for that object.

Example:

```
HIGH
Cross-account object access verified
VERIFIED

Endpoint:
GET /api/accounts/{account_id}

Evidence:
User B retrieved User A's object.
Cross-account HTTP 200 JSON matched the owner's baseline.

Stored:
- endpoint template
- parameter name
- status codes
- verification result

Not stored:
- authentication credentials
- raw object identifiers
```

This is intended to be actual authorization proof, not a heuristic OWASP label.

## Current checks

### Passive

- security headers
- cookie flags
- directory listing
- Swagger/OpenAPI exposure
- debug/stack traces
- exposed `.env`
- exposed `.git/HEAD`
- public source maps
- secret redaction

### Safe-active

- CORS arbitrary-origin reflection
- Open Redirect
- anonymous endpoint classification
- unauthenticated sensitive-looking JSON exposure

### Authenticated read-only

- auth boundary mapping
- user-specific response detection
- owned-ID discovery from authenticated JSON
- path-template matching
- cross-account object-read verification
- verified IDOR/BOLA finding

The rule remains:

**Discover -> Normalize -> Compare -> Verify -> Deduplicate -> Report.**

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

## Demo

Terminal 1:

```bash
python examples/vulnerable_app.py
```

Terminal 2:

```bash
magic-security http://127.0.0.1:8000 \
  --active \
  --auth-contexts examples/auth_contexts.example.json \
  --json reports/demo.json
```

The demo uses fake data and fake auth headers only.

It includes:

- `/api/me`
  - anonymous -> 401
  - User A -> own `account_id`
  - User B -> different own `account_id`

- `/api/accounts/{account_id}`
  - requires authentication
  - intentionally fails object ownership checks
  - either demo user can read either account
  - expected scanner result: **verified cross-account object access**

## JSON report

The report contains:

- normalized and raw endpoints
- anonymous endpoint observations
- auth-boundary comparisons
- IDOR template observations
- owner/cross-account status codes
- `cross_account_verified`
- finding fingerprints
- affected URLs / occurrence counts
- severity / confidence / verified status

It does **not** serialize:

- auth header values
- cookie values
- raw object identifiers used for IDOR verification
- authenticated response bodies

## Safety default

The MVP remains localhost/loopback only.

The IDOR/BOLA verifier:

- requires explicit test contexts
- performs GET requests only
- does not mutate application state
- does not brute-force object identifiers
- only reuses IDs discovered from the test users' own authenticated responses

Browser mode blocks cross-origin requests and does not click buttons or submit forms.

## Architecture

```
magic_security/
├── active.py
├── auth.py
├── browser.py
├── classifier.py
├── crawler.py
├── discovery.py
├── engine.py
├── fingerprints.py
├── idor.py
├── models.py
├── openapi.py
├── probes.py
├── reporting.py
├── surface.py
└── checks/
```

## Test

```bash
pytest
```

Tests run automatically through GitHub Actions.

## Next milestone

The next useful coverage jump is to make authenticated discovery richer:

- authenticated browser crawl for each test user
- collect user-specific API routes that only appear after login
- nested ownership relationships
- multiple test-role pairs
- safe session / CSRF checks

State-changing authorization tests remain out of scope until the read-only verifier is mature.
