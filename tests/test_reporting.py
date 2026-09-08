import json

from magic_security.models import (
    CrawlResult,
    EndpointCandidate,
    Finding,
    FindingKind,
    Severity,
)
from magic_security.reporting import build_report, write_json_report


def test_build_report_is_json_serializable(tmp_path):
    crawl = CrawlResult(target="http://localhost:8000")
    crawl.endpoints.add(
        EndpointCandidate(
            url="http://localhost:8000/api/users",
            method="GET",
            source="openapi",
            parameters=("limit",),
        )
    )
    crawl.parameters.add("limit")

    findings = [
        Finding(
            title="Demo finding",
            severity=Severity.MEDIUM,
            kind=FindingKind.EXPOSURE,
            url="http://localhost:8000",
            description="demo",
            evidence="verified evidence",
            remediation="fix it",
            confidence=1.0,
        )
    ]

    report = build_report(crawl, findings)
    encoded = json.dumps(report)

    assert '"verified": true' in encoded
    assert report["attack_surface"]["endpoints"] == 1
    assert report["findings"][0]["severity"] == "medium"

    destination = write_json_report(tmp_path / "scan.json", crawl, findings)
    assert destination.exists()
    assert json.loads(destination.read_text())["target"] == crawl.target
