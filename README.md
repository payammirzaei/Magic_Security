# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## Current pipeline

```
URL
 -> HTTP / Browser / OpenAPI Discovery
 -> Authenticated Browser Discovery (optional)
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

## Discovery

Magic_Security currently combines:

- same-origin HTTP crawling
- HTML links/forms/parameters
- frontend JavaScript API extraction
- OpenAPI / Swagger ingestion
- source-map discovery
- optional anonymous Playwright discovery
- optional authenticated Playwright discovery for every supplied test context
- endpoint normalization across all discovery sources

## Authenticated Browser Discovery

When both `--browser` and `--auth-contexts` are supplied, Playwright creates a separate isolated browser context for each test account.

Each context receives only its own:

- custom headers
- cookies

Then Magic_Security renders the target and same-origin pages without clicking buttons or submitting forms.

It captures:

- authenticated-only links
- authenticated-only forms
- XHR / fetch requests
- runtime query/body parameter names
- scripts loaded after authentication

Discovery provenance is context-aware.

Example:

```
GET /api/user-settings
sources:
  browser:user_a:network
  browser:user_b:network
```

Only the context name is stored. Header values, cookie values, tokens, and authenticated response bodies are not serialized.

## Anonymous response classification

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

The scanner can also verify sensitive-looking JSON fields exposed without authentication. Field names are reported; values are not stored.

## Test-account auth boundary mapping

Magic_Security can compare the same endpoint in three contexts:

```
Anonymous
User A
User B
```

Test contexts are supplied through a local JSON file.

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

## Verified read-only IDOR / BOLA

The object-level authorization verifier:

1. learns IDs from each user's own authenticated JSON
2. matches them to path templates such as `/api/accounts/{account_id}`
3. establishes owner baselines
4. cross-tests User A and User B
5. reports only when cross-account HTTP 200 JSON matches the owner's object response

No brute force is used. Only GET requests are issued.

Example finding:

```
HIGH
Cross-account object access verified
VERIFIED
```

The report does not contain authentication secrets or raw object identifiers used during verification.

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

- authenticated browser discovery
- auth boundary mapping
- user-specific response detection
- owned-ID discovery
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

## Full local demo

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

The demo uses fake data and fake auth headers only.

Authenticated browser discovery should additionally find:

- `/dashboard`, visible only to test users
- `/settings?tab=profile`
- runtime `GET /api/user-settings`

The normalized endpoint keeps provenance such as:

```
browser:user_a:network
browser:user_b:network
```

## JSON report

The report includes:

- normalized and raw endpoints
- anonymous browser pages
- authenticated browser pages per context
- authenticated browser network-request counts
- endpoint discovery provenance
- anonymous endpoint observations
- auth-boundary comparisons
- IDOR observations
- findings / fingerprints / affected URLs

It does **not** serialize:

- auth header values
- cookie values
- access tokens
- authenticated response bodies
- raw object IDs used for IDOR verification

## Safety default

The MVP remains localhost/loopback only.

Browser discovery:

- blocks cross-origin requests
- does not click buttons
- does not submit forms

IDOR/BOLA verification:

- requires explicit test contexts
- performs GET requests only
- does not mutate application state
- does not brute-force identifiers

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

Next useful coverage:

- nested ownership relationships
- multiple role pairs
- authenticated source-map/runtime asset discovery
- session-security checks
- safe CSRF verification

State-changing authorization tests remain out of scope until read-only verification is mature.
