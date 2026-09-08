# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## MVP pipeline

```
URL
 -> HTTP Crawl
 -> Browser Runtime Discovery (optional)
 -> Attack Surface Map
 -> Normalize Surface
 -> Security Checks
 -> Verification
 -> Fingerprint + Deduplicate
 -> Evidence
```

The current milestone intentionally has no SaaS layer: no auth, billing, database, queue, or frontend.

## Current capabilities

### Attack-surface discovery

- Same-origin HTTP crawl
- Pages, links, forms, parameters, and JavaScript assets
- API extraction from frontend JavaScript
- OpenAPI / Swagger ingestion
- JavaScript source-map discovery
- Optional Playwright runtime discovery for SPAs

### Attack-surface normalization

The same endpoint can be discovered several ways:

```
javascript:fetch   GET /api/users?limit=20
browser:network    GET /api/users?limit=50
openapi            GET /api/users
```

Magic_Security now reports one normalized endpoint:

```
GET /api/users
parameters: include, limit
sources: browser:network, javascript:fetch, openapi
```

Raw discoveries are still kept in the JSON report for traceability.

Normalization is intentionally conservative:

- query values are removed
- parameter names are merged
- discovery sources are merged
- HTTP methods remain separate
- path segments are not guessed or rewritten yet

### Response fingerprinting

Every HTTP page response gets a stable fingerprint based on status, normalized content type, and normalized response body. Obvious volatile UUIDs and long numeric IDs are normalized first.

Response fingerprints are for grouping/analysis only; they do not create vulnerability findings by themselves.

### Finding deduplication

Repeated root issues are merged before reporting while preserving:

- representative evidence
- all affected URLs
- occurrence count
- stable finding fingerprint
- highest observed severity/confidence

### Passive security checks

- Security-header hardening checks
- Cookie flag checks
- Directory-listing exposure
- Swagger/OpenAPI exposure
- Debug/stack-trace exposure heuristics
- Local probes for exposed `.env`, `.git/HEAD`, OpenAPI specs
- Verified public source-map exposure
- Secret values are redacted from findings

### Safe-active verification

Run with `--active`.

- CORS arbitrary-origin reflection
- Open Redirect

The core rule is:

**Discover -> Normalize -> Detect -> Verify -> Deduplicate -> Report.**

## Install

Base scanner:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Browser mode:

```bash
pip install -e ".[dev,browser]"
playwright install chromium
```

## Run

```bash
magic-security http://localhost:3000 --browser --active --json reports/scan.json
```

## JSON report

The report contains both:

- `normalized_endpoints` for the useful attack-surface view
- `raw_endpoints` for discovery provenance/evidence

It also contains response groups, finding fingerprints, affected URLs, occurrence counts, severity, confidence, and verified status.

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

- richer JavaScript route extraction
- browser-discovered source maps
- endpoint response classification
- authenticated/test-account mode later
