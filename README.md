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
- OpenAPI / Swagger ingestion
- JavaScript source-map discovery
- **Playwright browser discovery**
  - dynamically rendered links
  - runtime forms and fields
  - same-origin XHR / fetch requests
  - request methods
  - query parameters
  - JSON/form body field names
  - same-origin scripts loaded at runtime

Browser mode does **not** click buttons or submit forms. It renders discovered pages and observes runtime network behavior.

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

- CORS arbitrary-origin reflection
- Open Redirect

The core rule is:

**Detect -> Verify -> Report.**

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

HTTP-only:

```bash
magic-security http://localhost:3000
```

HTTP + browser discovery:

```bash
magic-security http://localhost:3000 --browser
```

Full current local scan:

```bash
magic-security http://localhost:3000 --browser --active --json reports/scan.json
```

## Browser safety behavior

The browser crawler is still local-first:

- target must be localhost/loopback
- browser requests outside the target origin are blocked
- no button clicking
- no automatic form submission
- no state-changing workflow exploration

This keeps runtime discovery useful without turning the crawler into an uncontrolled browser bot.

## Run the intentionally vulnerable demo

Terminal 1:

```bash
python examples/vulnerable_app.py
```

Terminal 2:

```bash
magic-security http://127.0.0.1:8000 --browser --active --json reports/demo.json
```

The demo intentionally contains **fake-only** security problems.

## JSON report

The JSON report contains:

- attack-surface counts
- browser-rendered pages
- normalized endpoints
- discovery source
- parameters
- findings
- severity
- confidence
- verified status

## Test

```bash
pytest
```

Tests also run automatically through GitHub Actions on pushes and pull requests.

## Architecture

```
magic_security/
├── active.py
├── browser.py
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

- richer JavaScript route extraction
- response fingerprinting + finding deduplication
- browser-discovered source maps
- authenticated/test-account mode later

The MVP remains local-first until the scanner core is trustworthy.
