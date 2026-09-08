# Magic_Security

A local-first web security scanner focused on evidence, not checklist noise.

## MVP goal

```
URL -> Crawl -> Discover -> Check -> Verify -> Evidence
```

The first milestone intentionally has no SaaS layer: no auth, billing, database, queue, or frontend.

### Current capabilities

- Same-origin HTTP crawler
- Security header hardening checks
- Cookie flag checks
- Directory-listing exposure detection
- Swagger/OpenAPI exposure detection from crawled pages
- Debug/stack-trace exposure heuristics
- Local-only probes for exposed `.env`, `.git/HEAD`, `openapi.json`, and `swagger.json`
- Findings separated into Vulnerability / Exposure / Hardening
- Evidence and confidence attached to every finding

## Safety default

Remote targets are blocked by default. The MVP is meant for localhost testing.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run

```bash
magic-security http://localhost:3000
```

or:

```bash
python -m magic_security http://127.0.0.1:8000
```

## Test

```bash
pytest
```

## Architecture

```
magic_security/
├── crawler.py
├── engine.py
├── models.py
├── probes.py
└── checks/
    ├── base.py
    ├── cookies.py
    ├── exposures.py
    └── headers.py
```

Next milestone: richer attack-surface discovery (forms, parameters, JS/API endpoints) and verified safe-active checks.
