from __future__ import annotations

import subprocess
import sys

from magic_security import __version__
from magic_security.models import CrawlResult
from magic_security.reporting import build_report
from magic_security.version import (
    REPORT_SCHEMA_VERSION,
    SCANNER_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
)


def test_package_and_schema_versions_are_consistent():
    assert __version__ == SCANNER_VERSION == "1.3.0"
    assert REPORT_SCHEMA_VERSION == 2
    assert SNAPSHOT_SCHEMA_VERSION == 2


def test_cli_version_output():
    result = subprocess.run(
        [sys.executable, "-m", "magic_security", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert SCANNER_VERSION in (result.stdout + result.stderr)


def test_report_includes_schema_and_scanner_version():
    report = build_report(CrawlResult(target="http://127.0.0.1:8000"), [])
    assert report["report_schema_version"] == REPORT_SCHEMA_VERSION
    assert report["scanner_version"] == SCANNER_VERSION
