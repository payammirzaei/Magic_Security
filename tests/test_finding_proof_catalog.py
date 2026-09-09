"""STEP 59 — finding proof contracts (vulnerability must not be regex-only)."""

from __future__ import annotations

from pathlib import Path


from magic_security.models import FindingKind


PROOF_CATALOG = Path(__file__).resolve().parents[1] / "docs" / "FINDING_PROOF_CATALOG.md"


REQUIRED_VULN_CHECKS = [
    "injection.html.reflected",
    "idor.cross_account",
    "parameter.ssti",
    "parameter.crlf",
    "server.path_traversal",
    "active.open_redirect",
]


def test_proof_catalog_exists_and_lists_vuln_checks():
    assert PROOF_CATALOG.exists(), "docs/FINDING_PROOF_CATALOG.md missing"
    text = PROOF_CATALOG.read_text(encoding="utf-8")
    for check_id in REQUIRED_VULN_CHECKS:
        assert check_id in text, f"missing proof entry for {check_id}"
    assert "baseline" in text.lower()
    assert "mutation" in text.lower()
    assert "negative" in text.lower()


def test_vulnerability_enum_still_distinct():
    assert FindingKind.VULNERABILITY.value == "vulnerability"
    assert FindingKind.EXPOSURE.value == "exposure"
