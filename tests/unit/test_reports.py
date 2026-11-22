"""
Unit tests for Multi-Format Report Generator.
Verifies rendering of all 15 intelligence sections in HTML and Markdown.
"""

from pathlib import Path
from datetime import datetime, timezone
from devixon.database.models import (
    Assessment,
    Finding,
    Asset,
    Evidence,
    Subdomain,
    LiveHost,
    DiscoveredPath,
    InternalLink,
    Endpoint,
    Parameter,
    Technology,
)
from devixon.reports.generator import ReportGenerator


def test_report_generation_all_formats(tmp_path: Path):
    generator = ReportGenerator()
    assessment = Assessment(
        id="test-ass-1234",
        target="example.com",
        scope_profile_json='{"primary_domain": "example.com", "authorized_by_user": true}',
        scan_profile="FULL",
        status="COMPLETED",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    asset = Asset(
        hostname="api.example.com",
        ip_address="93.184.216.34",
        asset_type="SUBDOMAIN",
        scope_status="IN_SCOPE",
        discovery_source="TEST",
    )
    sub = Subdomain(
        assessment_id=assessment.id,
        subdomain="api.example.com",
        resolved_ip="93.184.216.34",
        resolution_status="RESOLVED",
        discovery_source="SUBFINDER",
    )
    lh = LiveHost(
        assessment_id=assessment.id,
        url="https://api.example.com",
        host="api.example.com",
        status_code=200,
        title="API Gateway",
        web_server="nginx/1.24",
        response_time_ms=45.2,
    )
    dp = DiscoveredPath(
        assessment_id=assessment.id,
        host="api.example.com",
        url="https://api.example.com/api/v1",
        path="/api/v1",
        status_code=200,
        content_length=150,
        discovery_tool="FFUF",
    )
    link = InternalLink(
        assessment_id=assessment.id,
        source_url="https://api.example.com",
        destination_url="https://api.example.com/docs",
        method="GET",
        link_type="a_href",
        is_internal=True,
        crawl_depth=1,
    )
    ep = Endpoint(
        assessment_id=assessment.id,
        url="https://api.example.com/users",
        path="/users",
        method="GET",
        params="id,page",
        is_historical=False,
    )
    param = Parameter(
        assessment_id=assessment.id,
        endpoint_id=ep.id,
        name="id",
        param_type="query",
        example_value="101",
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
    generator.generate_html(
        assessment=assessment,
        findings=[finding],
        assets=[asset],
        output_path=html_path,
        subdomains=[sub],
        live_hosts=[lh],
        discovered_paths=[dp],
        internal_links=[link],
        endpoints=[ep],
        parameters=[param],
    )
    assert html_path.exists()
    html_txt = html_path.read_text(encoding="utf-8")
    assert "DEVIXON" in html_txt
    assert "Missing HSTS Header" in html_txt
    assert "api.example.com" in html_txt
    assert "/api/v1" in html_txt
    assert "Executive Summary" in html_txt
    assert "Scope Information" in html_txt
    assert "Subdomain Inventory" in html_txt
    assert "Live Hosts" in html_txt
    assert "Discovered Directories and Files" in html_txt

    # 2. Markdown
    md_path = tmp_path / "report.md"
    generator.generate_markdown(
        assessment=assessment,
        findings=[finding],
        assets=[asset],
        output_path=md_path,
        subdomains=[sub],
        live_hosts=[lh],
        discovered_paths=[dp],
        internal_links=[link],
        endpoints=[ep],
        parameters=[param],
    )
    assert md_path.exists()
    md_txt = md_path.read_text(encoding="utf-8")
    assert "DEVIXON" in md_txt
    assert "## 1. Executive Summary" in md_txt
    assert "## 2. Scope Information" in md_txt
    assert "## 3. Subdomain Inventory" in md_txt
    assert "## 5. Live Hosts" in md_txt
    assert "## 7. Discovered Directories and Files" in md_txt

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
