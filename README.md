# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## Current pipeline

```
URL
 -> HTTP Crawl
 -> Browser Runtime Discovery (optional)
 -> OpenAPI / JS Discovery
 -> Normalize Attack Surface
 -> Endpoint Response Classification
 -> Security Checks
 -> Safe-Active Verification
 -> Fingerprint + Deduplicate
 -> Evidence Report
```

The current milestone intentionally has no SaaS layer: no auth, billing, database, queue, or frontend.

## Attack-surface discovery

Magic_Security currently combines:

- same-origin HTTP crawling
- HTML links/forms/parameters
- frontend JavaScript API extraction
- OpenAPI / Swagger ingestion
- JavaScript source-map discovery
- optional Playwright runtime discovery for SPAs

Multiple discoveries of the same route are normalized into one endpoint while raw provenance is preserved.

Example:

```
GET /api/users
parameters: include, limit
sources: browser:network, javascript:fetch, openapi
```

## Endpoint response classification

When `--active` is enabled, GET endpoints without unresolved path templates are requested **without authentication or session cookies** and classified as:

- `auth_required` — HTTP 401/403
- `json`
- `html`
- `redirect`
- `not_found`
- `client_error`
- `server_error`
- `empty`
- `other`

This gives later authorization checks a real map of the API surface instead of blindly attacking every route.

### Verified unauthenticated data exposure

For HTTP 200 JSON responses, the scanner inspects **field names only**.

Examples of security-relevant fields include:

- email / phone / address
- DOB
- IBAN / bank-account fields
- password / secret / API-key / token-like fields

If such fields are returned without auth, Magic_Security emits a verified **Exposure**.

Response values are never stored in the finding evidence.

Example:

```
MEDIUM
Unauthenticated JSON exposes sensitive-looking fields
Verified: YES

Endpoint:
GET /api/users

Evidence:
users.email
users.phone

Values stored:
NO
```

Secret-like fields receive higher severity than ordinary personal-data-looking fields.

This is intentionally not promoted to a stronger exploit claim until authenticated/contextual testing proves the actual authorization impact.

## Existing security checks

### Passive

- Security headers
- Cookie flags
- Directory listing
- Swagger/OpenAPI exposure
- Debug/stack traces
- exposed `.env`
- exposed `.git/HEAD`
- source maps
- secret redaction

### Safe-active

- CORS arbitrary-origin reflection
- Open Redirect
- endpoint response classification
- unauthenticated sensitive-looking JSON exposure

The core rule remains:

**Discover -> Normalize -> Detect -> Verify -> Deduplicate -> Report.**

## Response fingerprinting and deduplication

Repeated root issues are merged while preserving:

- representative evidence
- all affected URLs
- occurrence count
- stable finding fingerprint
- highest observed severity/confidence

HTTP responses are also fingerprinted for grouping. Response similarity alone never creates a vulnerability.

## Install

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

## Full local scan

```bash
magic-security http://localhost:3000 --browser --active --json reports/scan.json
```

## Vulnerable demo

Terminal 1:

```bash
python examples/vulnerable_app.py
```

Terminal 2:

```bash
magic-security http://127.0.0.1:8000 --active --json reports/demo.json
```

The demo uses fake data only. It contains:

- exposed fake `.env`
- fake Git metadata
- public source map
- directory listing
- OpenAPI docs
- open redirect
- unsafe CORS
- unauthenticated fake personal-data JSON
- a separate API endpoint returning HTTP 401

## JSON report

The report contains:

- normalized endpoints
- raw endpoint discovery provenance
- endpoint response classifications
- sensitive/secret field names only
- response fingerprint groups
- finding fingerprints
- affected URLs
- occurrence counts
- severity
- confidence
- verified status

## Safety default

The MVP remains localhost/loopback only.

Browser mode blocks cross-origin requests and does not click buttons or submit forms.

## Test

```bash
pytest
```

Tests also run automatically through GitHub Actions.

## Architecture

```
magic_security/
├── active.py
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

The next major jump in real security coverage is an **authenticated test-account mode**:

- Session A / Session B
- auth-boundary mapping
- object-ID candidate discovery
- cross-account access comparison
- IDOR / BOLA verification

That is where Magic_Security starts proving broken authorization instead of only mapping unauthenticated behavior.
