# Magic Security — Quick Start & Safe Use (STEP 50 docs slice)

## Quick start

```bash
pip install -e ".[dev,browser]"
python examples/vulnerable_app.py   # separate terminal
magic-security http://127.0.0.1:8000 --active --browser \
  --auth-contexts examples/auth_contexts.example.json \
  --json report.json --html report.html --snapshot snap.json
```

## Scan profiles

| Profile | Use |
|---------|-----|
| Local default | localhost only; optional `--active` / `--browser` / `--auth-contexts` |
| Workflows | disposable auth contexts or `--workflows` |
| Production-safe remote | `production_safe_remote_profile()` + verified registry entry |

## Safe-use rules

- Never scan systems you do not own/authorize.
- Remote **active** scans require a **VERIFIED** target registry entry.
- Workflows mutate only disposable resources and always attempt cleanup.
- Reports/snapshots must not contain secrets (redaction is mandatory).

## Auth contexts

See `examples/auth_contexts.example.json`. Mark disposable test users with `"disposable": true`.

## Workflows

JSON/YAML workflow schema in `magic_security/workflow_schema.py`. Unsafe bodies fail before network.

## Remote verification

```bash
magic-security target add https://staging.example.com
magic-security target verify https://staging.example.com
```

## Repository mode

```bash
magic-security http://127.0.0.1:8000 --repo path/to/source --json report.json
```

Source findings are labeled `evidence_source=source` and never auto-promote to verified runtime vulnerabilities.

## Backtesting / CI

```bash
magic-security http://127.0.0.1:8000 --snapshot current.json --baseline baseline.json --fail-on-policy
```

GitHub Actions example: `.github/workflows/security-regression.yml`.

## Local API / dashboard

```bash
pip install -e ".[api]"
uvicorn magic_security.api:create_app --factory
```

Write dashboard HTML via `magic_security.dashboard.write_dashboard`.

## Schemas

- Report schema: `REPORT_SCHEMA_VERSION` (v2)
- Snapshot schema: `SNAPSHOT_SCHEMA_VERSION` (v2; v1 migrates on load)
