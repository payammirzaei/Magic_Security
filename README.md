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

### Security checks

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
- Findings are separated into:
  - Vulnerability
  - Exposure
  - Hardening

## Safety default

Remote targets are blocked by default. The MVP is intentionally localhost/loopback only.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run against your local app

```bash
magic-security http://localhost:3000
```

or:

```bash
python -m magic_security http://127.0.0.1:8000
```

## Run the intentionally vulnerable demo

Terminal 1:

```bash
python examples/vulnerable_app.py
```

Terminal 2:

```bash
magic-security http://127.0.0.1:8000
```

The demo intentionally contains **fake-only** security problems. The scanner should discover surfaces such as:

```
GET  /api/users?limit=20
POST /api/orders
GET  /graphql
GET  /search          params=q,category
GET  /products        params=page,sort
```

It should also verify exposures including the fake `.env`, fake Git metadata, debug output, directory listing, OpenAPI docs, and a public source map.

## Test

```bash
pytest
```

Tests also run automatically through GitHub Actions on pushes and pull requests.

## Architecture

```
magic_security/
├── crawler.py
├── discovery.py
├── engine.py
├── models.py
├── probes.py
└── checks/
    ├── base.py
    ├── cookies.py
    ├── exposures.py
    └── headers.py
```

## Next milestone

First safe-active verification modules:

- CORS behavior
- Open redirect
- low-risk rate-limit observation

The rule stays the same:

**Detect -> Verify -> Report.**
