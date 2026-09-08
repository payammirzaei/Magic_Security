# Magic_Security

A local-first web security scanner focused on **evidence, not checklist noise**.

## MVP pipeline

```
URL
 -> Crawl
 -> Attack Surface Map
 -> Security Checks
 -> Verification
 -> Evidence
```

The current milestone intentionally has no SaaS layer: no auth, billing, database, queue, or frontend.

## Current capabilities

### Attack-surface discovery

- Same-origin HTTP crawl
- Pages and links
- HTML forms + methods
- Input/select/textarea parameter names
- Query-string parameter discovery
- JavaScript asset discovery
- API extraction from:
  - `fetch(...)`
  - `axios.get/post/put/patch/delete(...)`
  - `$.get(...)` / `$.post(...)`
  - obvious `/api`, `/graphql`, `/rest`, and versioned API strings
- Endpoint method + discovery source tracking
- JavaScript source-map discovery
- **OpenAPI / Swagger ingestion**
  - paths
  - HTTP methods
  - query/path parameters
  - simple JSON request-body properties

### Passive security checks

- Security-header hardening checks
- Cookie flag checks
- Directory-listing exposure
- Swagger/OpenAPI exposure
- Debug/stack-trace exposure heuristics
- Local probes for exposed:
  - `.env`
  - `.git/HEAD`
  - `openapi.json`
  - `swagger.json`
- Verified public source-map exposure
- Secret values are redacted from findings

### Safe-active verification

Run with `--active`.

- **CORS arbitrary-origin reflection**
  - verifies the server actually reflects a controlled untrusted Origin
  - detects credential-enabled reflection separately
  - reports this as an **Exposure**, not fake proof of data theft
- **Open Redirect**
  - tests only discovered redirect-like parameters such as `next`, `return_url`, or `redirect_uri`
  - requires a real 3xx response pointing at the scanner-controlled test origin
  - reports only after reproduction

The core rule is:

**Detect -> Verify -> Report.**

Findings are separated into Vulnerability / Exposure / Hardening.

## JSON report

```bash
magic-security http://localhost:3000 --active --json reports/scan.json
```

The JSON contains attack-surface counts, normalized endpoints, parameters, findings, severity, confidence, and verified status.

## Safety default

Remote targets are blocked by default. The MVP is intentionally localhost/loopback only.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run the intentionally vulnerable demo

Terminal 1:

```bash
python examples/vulnerable_app.py
```

Terminal 2:

```bash
magic-security http://127.0.0.1:8000 --active --json reports/demo.json
```

The demo intentionally contains **fake-only** security problems.

## Test

```bash
pytest
```

Tests also run automatically through GitHub Actions on pushes and pull requests.

## Architecture

```
magic_security/
├── active.py
├── crawler.py
├── discovery.py
├── engine.py
├── models.py
├── openapi.py
├── probes.py
├── reporting.py
└── checks/
```

## Next milestone

- browser crawler (Playwright) for JS-heavy SPAs
- richer JavaScript route extraction
- response fingerprinting / deduplication
- authenticated/test-account mode later

The MVP remains local-first until the scanner core is trustworthy.
