"""Single source of truth for scanner and schema versions."""

from __future__ import annotations

# Package / CLI scanner version (keep in sync with pyproject.toml).
SCANNER_VERSION = "1.3.0"

# JSON report document schema (independent of package version).
REPORT_SCHEMA_VERSION = 2

# Compact security snapshot schema (independent of package version).
# v2 adds scan_profile, evidence fingerprints, optional deploy metadata.
SNAPSHOT_SCHEMA_VERSION = 2

# Oldest snapshot schema still loadable (migrated in-memory to current).
SNAPSHOT_SCHEMA_MIN_SUPPORTED = 1
