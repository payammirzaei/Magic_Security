"""STEP 60 / 61 — false positive & false negative corpus markers."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_safe_app_exists_for_false_positive_corpus():
    path = ROOT / "examples" / "safe_app.py"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "custom-404-as-200" in text
    assert "HTML-encoded" in text or "encoded" in text.lower()
    assert "docs-only-not-real" in text


def test_vulnerable_app_covers_false_negative_minimums():
    text = (ROOT / "examples" / "vulnerable_app.py").read_text(encoding="utf-8")
    required_signals = [
        "reflect",
        "xss",
        "cors",
        "graphql",
        "download",
        "fetch",
        "login",
        "notes",
        "upload",
        "ssti",
        "redirect",
        "go",
    ]
    lowered = text.lower()
    missing = [s for s in required_signals if s not in lowered]
    assert missing == [], f"vulnerable_app missing FN fixtures: {missing}"


FN_CHECK_IDS = [
    "injection.html.reflected",
    "idor",
    "cors",
    "ssti",
    "crlf",
    "traversal",
    "ssrf",
    "redirect",
    "graphql",
    "websocket",
    "upload",
]


def test_fn_check_ids_registered_or_documented():
    catalog = (ROOT / "docs" / "FINDING_PROOF_CATALOG.md").read_text(encoding="utf-8")
    registry = (ROOT / "magic_security" / "registry.py").read_text(encoding="utf-8")
    blob = catalog + registry
    for stub in FN_CHECK_IDS:
        assert stub.lower() in blob.lower(), f"FN coverage missing mention of {stub}"
