# v1.1 Frozen Baseline Fixtures

Frozen during **STEP 1** of `docs/CURSOR_50_STEP_BUILD_PLAN.md`.

## Files

| File | Purpose |
|------|---------|
| `v1.1_canonical_report.json` | Full JSON report from a representative local demo scan |
| `v1.1_canonical_snapshot.json` | Compact security backtesting snapshot (`schema_version: 1`) |
| `MANIFEST.json` | Regeneration metadata (version, command, test count) |

## Regeneration

```bash
python examples/vulnerable_app.py
# then, in another shell:
magic-security http://127.0.0.1:8000 \
  --browser --active \
  --auth-contexts examples/auth_contexts.example.json \
  --json tests/fixtures/baseline/v1.1_canonical_report.json \
  --snapshot tests/fixtures/baseline/v1.1_canonical_snapshot.json
```

These fixtures are a historical baseline for refactor safety. They are **not** assert-equal golden files for every future scan (timestamps and some dynamic fields will differ).
