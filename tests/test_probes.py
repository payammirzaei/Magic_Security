from magic_security.probes import _redacted_env_evidence


def test_env_evidence_redacts_values():
    body = "DATABASE_URL=postgres://user:secret@db/app\nAPI_KEY=abc123\nDEBUG=true"
    evidence = _redacted_env_evidence(body)
    assert "DATABASE_URL" in evidence
    assert "API_KEY" in evidence
    assert "postgres://user:secret" not in evidence
    assert "abc123" not in evidence
