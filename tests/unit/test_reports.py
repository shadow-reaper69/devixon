"""
Unit tests for Multi-Format Report Generator.
"""

from pathlib import Path
from datetime import datetime, timezone
from devixon.database.models import Assessment, Finding, Asset, Evidence
from devixon.reports.generator import ReportGenerator


def test_report_generation_all_formats(tmp_path: Path):
    generator = ReportGenerator()
    assessment = Assessment(
        id="test-ass-1234",
        target="example.com",
        scan_profile="QUICK",
        status="COMPLETED",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
    )
    asset = Asset(
        hostname="api.example.com",
        ip_address="93.184.216.34",
        asset_type="SUBDOMAIN",
        scope_status="IN_SCOPE",
        discovery_source="TEST",
    )
    finding = Finding(
        id="find-5678",
        title="Missing HSTS Header",
        category="Security Misconfiguration",
        severity="LOW",
        cvss_score=3.7,
        verification_status="CONFIRMED",
        confidence="CONFIRMED",
        description="The Strict-Transport-Security header is not present.",
        impact="Man-in-the-middle attacks may downgrade connection.",
        reproduction_steps="curl -I https://api.example.com",
        remediation="Enable HSTS with max-age=31536000",
    )
    evidence = Evidence(
        finding_id=finding.id,
        evidence_type="HTTP_HEADER",
        description="HTTP Response Headers",
        sanitized_data="Server: nginx\nContent-Type: text/html",
        source="TEST",
    )
    finding.evidence.append(evidence)

    # 1. HTML
    html_path = tmp_path / "report.html"
    generator.generate_html(assessment, [finding], [asset], html_path)
    assert html_path.exists()
    assert "DEVIXON" in html_path.read_text(encoding="utf-8")
    assert "Missing HSTS Header" in html_path.read_text(encoding="utf-8")

    # 2. Markdown
    md_path = tmp_path / "report.md"
    generator.generate_markdown(assessment, [finding], [asset], md_path)
    assert md_path.exists()
    assert "# Security Assessment Report" in md_path.read_text(encoding="utf-8")

    # 3. JSON
    json_path = tmp_path / "report.json"
    generator.generate_json(assessment, [finding], [asset], json_path)
    assert json_path.exists()
    assert "test-ass-1234" in json_path.read_text(encoding="utf-8")

    # 4. CSV
    csv_path = tmp_path / "report.csv"
    generator.generate_csv([finding], csv_path)
    assert csv_path.exists()
    assert "Missing HSTS Header" in csv_path.read_text(encoding="utf-8")
