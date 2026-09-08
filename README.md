# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## Current pipeline

```
URL
 -> HTTP / Browser / OpenAPI Discovery
 -> Normalize Attack Surface
 -> Anonymous Endpoint Classification
 -> Test-Account Auth Boundary Mapping
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

### Test-account auth boundary mapping

Magic_Security can now compare the same endpoint in three contexts:

```
Anonymous
User A
User B
```

The user supplies two local test contexts through a JSON file. A context can contain test headers and/or cookies.

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

A ready-to-copy fake example is included at:

```
examples/auth_contexts.example.json
```

Run:

```bash
magic-security http://127.0.0.1:8000 \
  --active \
  --auth-contexts examples/auth_contexts.example.json \
  --json reports/demo.json
```

### Boundary classifications

For every eligible GET endpoint the report can mark:

- `protected`
  - anonymous is denied
  - at least one test user is allowed

- `public_or_unprotected`
  - anonymous and test users are all allowed

- `denied_for_all`
  - anonymous and test users are denied

- `inconsistent`
  - access behavior differs in an unexpected way

- `unknown`

It also records whether the authenticated users receive different response fingerprints:

```
authenticated_responses_differ: true
```

That is useful for finding **user-specific endpoints** to inspect in the next IDOR/BOLA phase.

## Important privacy behavior

Auth credentials are local input only.

Magic_Security does **not** write these into the scan report:

- cookie values
- authorization tokens
- custom header values
- response bodies from authenticated contexts

The JSON report contains only:

- context names
- endpoint
- status codes
- boundary classification
- whether authenticated response fingerprints differ

Suggested local filenames are already gitignored:

```
auth_contexts.local.json
.magic-security-auth.json
```

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
- auth-boundary mapping with explicit test contexts

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

It now includes:

- `/api/me`
  - anonymous -> 401
  - User A -> 200 with A-specific response
  - User B -> 200 with B-specific response
  - expected boundary: `protected`
  - authenticated responses differ: `true`

- `/api/public`
  - all contexts -> 200
  - expected boundary: `public_or_unprotected`

## JSON report

The report contains:

- normalized + raw endpoints
- anonymous endpoint observations
- auth boundary comparisons
- response fingerprint groups
- finding fingerprints
- affected URLs / occurrence counts
- severity / confidence / verified status

No test-account secret values are serialized.

## Safety default

The MVP remains localhost/loopback only.

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
├── models.py
├── openapi.py
├── probes.py
├── reporting.py
├── surface.py
└── checks/
```

## Next milestone

Next comes the first **IDOR / BOLA candidate engine**:

1. identify protected, user-specific endpoints
2. discover object-ID parameters / path candidates
3. learn a resource belonging to User A
4. replay only that resource identifier using User B's test context
5. report a vulnerability only if User B receives User A's resource

That will follow the same rule as the rest of the scanner:

**No proof -> no vulnerability.**
