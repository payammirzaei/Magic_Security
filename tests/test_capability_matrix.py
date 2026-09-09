from __future__ import annotations

from pathlib import Path


def test_capability_matrix_exists_and_lists_checks():
    path = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "CAPABILITY_MATRIX.yaml"
    )
    text = path.read_text(encoding="utf-8")
    assert "capabilities:" in text
    assert "coverage_categories:" in text
    assert "authorization.bola.read" in text
    assert "xss.reflected.execution" in text
    assert "why_partial:" in text
    # Honesty: no Fully Tested claim for single-variant categories
    assert "Fully Tested" not in text
