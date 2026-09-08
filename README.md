# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## MVP pipeline

```
URL
 -> HTTP Crawl
 -> Browser Runtime Discovery (optional)
 -> Attack Surface Map
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

### Response fingerprinting

Every HTTP page response gets a stable fingerprint based on:

- HTTP status
- normalized content type
- normalized response body

Obvious volatile UUIDs and long numeric IDs are normalized first. Response fingerprints are **only used for grouping/analysis**; they do not by themselves create a vulnerability finding.

### Finding deduplication

Repeated root issues are merged before reporting.

Example:

```
Missing Content-Security-Policy
Affected URLs: 37
Occurrences: 37
Fingerprint: 7f...
```

instead of 37 separate findings.

The report keeps:

- one root finding
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

**Detect -> Verify -> Deduplicate -> Report.**

Findings are separated into Vulnerability / Exposure / Hardening.

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

The JSON report now includes:

- attack-surface counts
- response fingerprint groups
- browser-rendered pages
- normalized endpoints
- finding fingerprints
- affected URL lists
- occurrence counts
- severity
- confidence
- verified status

## Safety default

The MVP remains localhost/loopback only.

Browser mode:

- blocks cross-origin requests
- does not click buttons
- does not submit forms
- does not explore state-changing workflows

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
└── checks/
```

## Next milestone

- richer JavaScript route extraction
- browser-discovered source maps
- attack-surface normalization across HTTP/browser/OpenAPI sources
- authenticated/test-account mode later
