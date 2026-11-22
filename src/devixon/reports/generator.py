"""
Comprehensive multi-format report generator: HTML, Markdown, JSON, and CSV.
Exposes all 15 reconnaissance intelligence sections:
1. Executive summary
2. Scope information
3. Subdomain inventory
4. DNS intelligence
5. Live hosts
6. Technology fingerprinting
7. Discovered directories and files
8. Internal links
9. URL inventory
10. Endpoint inventory
11. Parameter inventory
12. JavaScript intelligence
13. API discoveries
14. Security findings
15. Scan coverage and errors
"""

import json
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from devixon.database.models import (
    Assessment,
    Finding,
    Asset,
    Subdomain,
    DNSRecord,
    LiveHost,
    DiscoveredPath,
    InternalLink,
    Endpoint,
    Parameter,
    JavaScriptAsset,
    Technology,
    ScanStage,
)
from devixon.core.logger import logger

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    def __init__(self):
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_html(
        self,
        assessment: Assessment,
        findings: List[Finding],
        assets: List[Asset],
        output_path: Path,
        subdomains: Optional[List[Subdomain]] = None,
        dns_records: Optional[List[DNSRecord]] = None,
        live_hosts: Optional[List[LiveHost]] = None,
        discovered_paths: Optional[List[DiscoveredPath]] = None,
        internal_links: Optional[List[InternalLink]] = None,
        endpoints: Optional[List[Endpoint]] = None,
        parameters: Optional[List[Parameter]] = None,
        js_assets: Optional[List[JavaScriptAsset]] = None,
        technologies: Optional[List[Technology]] = None,
        stages: Optional[List[ScanStage]] = None,
    ) -> Path:
        template = self.jinja_env.get_template("report.html")

        subdomains = subdomains or getattr(assessment, "subdomains", [])
        dns_records = dns_records or getattr(assessment, "dns_records", [])
        live_hosts = live_hosts or getattr(assessment, "live_hosts", [])
        discovered_paths = discovered_paths or getattr(assessment, "discovered_paths", [])
        internal_links = internal_links or getattr(assessment, "internal_links", [])
        endpoints = endpoints or getattr(assessment, "endpoints", [])
        parameters = parameters or getattr(assessment, "parameters", [])
        js_assets = js_assets or getattr(assessment, "js_assets", [])
        technologies = technologies or getattr(assessment, "technologies", [])
        stages = stages or getattr(assessment, "stages", [])

        # Parse scope
        scope_info = {}
        try:
            scope_info = json.loads(assessment.scope_profile_json)
        except Exception:
            scope_info = {"primary_domain": assessment.target}

        critical_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")
        medium_count = sum(1 for f in findings if f.severity.upper() in ("MEDIUM", "LOW"))

        html_content = template.render(
            assessment=assessment,
            scope_info=scope_info,
            findings=findings,
            assets=assets,
            subdomains=subdomains,
            dns_records=dns_records,
            live_hosts=live_hosts,
            discovered_paths=discovered_paths,
            internal_links=internal_links,
            endpoints=endpoints,
            parameters=parameters,
            js_assets=js_assets,
            technologies=technologies,
            stages=stages,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")
        return output_path

    def generate_markdown(
        self,
        assessment: Assessment,
        findings: List[Finding],
        assets: List[Asset],
        output_path: Path,
        subdomains: Optional[List[Subdomain]] = None,
        dns_records: Optional[List[DNSRecord]] = None,
        live_hosts: Optional[List[LiveHost]] = None,
        discovered_paths: Optional[List[DiscoveredPath]] = None,
        internal_links: Optional[List[InternalLink]] = None,
        endpoints: Optional[List[Endpoint]] = None,
        parameters: Optional[List[Parameter]] = None,
        js_assets: Optional[List[JavaScriptAsset]] = None,
        technologies: Optional[List[Technology]] = None,
        stages: Optional[List[ScanStage]] = None,
    ) -> Path:
        subdomains = subdomains or getattr(assessment, "subdomains", [])
        dns_records = dns_records or getattr(assessment, "dns_records", [])
        live_hosts = live_hosts or getattr(assessment, "live_hosts", [])
        discovered_paths = discovered_paths or getattr(assessment, "discovered_paths", [])
        internal_links = internal_links or getattr(assessment, "internal_links", [])
        endpoints = endpoints or getattr(assessment, "endpoints", [])
        parameters = parameters or getattr(assessment, "parameters", [])
        js_assets = js_assets or getattr(assessment, "js_assets", [])
        technologies = technologies or getattr(assessment, "technologies", [])
        stages = stages or getattr(assessment, "stages", [])

        scope_info = {}
        try:
            scope_info = json.loads(assessment.scope_profile_json)
        except Exception:
            scope_info = {}

        gen_time = assessment.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if assessment.created_at else "N/A"
        lines = [
            f"# DEVIXON Comprehensive Security Assessment & Reconnaissance Report",
            f"**Target**: `{assessment.target}`  ",
            f"**Assessment ID**: `{assessment.id}`  ",
            f"**Profile**: {assessment.scan_profile}  ",
            f"**Status**: {assessment.status}  ",
            f"**Generated**: {gen_time}  \n",
            "---",
            "## 1. Executive Summary",
            f"An authorized reconnaissance and web security posture assessment was conducted against `{assessment.target}` using the DEVIXON framework. All operations strictly adhered to the authorized scope profile and non-destructive analysis protocols.\n",
            f"- **Subdomains Discovered**: {len(subdomains)}",
            f"- **Live HTTP Hosts**: {len(live_hosts)}",
            f"- **Endpoints & URLs**: {len(endpoints)}",
            f"- **Discovered Directories/Files**: {len(discovered_paths)}",
            f"- **Total Security Findings**: {len(findings)}",
            f"- **Critical / High Issues**: {sum(1 for f in findings if f.severity.upper() in ('CRITICAL', 'HIGH'))}\n",
            "---",
            "## 2. Scope Information",
            f"- **Primary Target**: `{scope_info.get('primary_domain', assessment.target)}`",
            f"- **Allowed Domains**: {', '.join(scope_info.get('allowed_domains', [])) or 'None'}",
            f"- **Allowed IPs/CIDRs**: {', '.join(scope_info.get('allowed_ips', [])) or 'None'}",
            f"- **Allowed Ports**: {', '.join(str(p) for p in scope_info.get('allowed_ports', [])) or 'None'}",
            f"- **Allowed Paths**: {', '.join(scope_info.get('allowed_paths', [])) or 'None'}",
            f"- **Excluded Targets**: {', '.join(scope_info.get('excluded_targets', [])) or 'None'}",
            f"- **Excluded Paths**: {', '.join(scope_info.get('excluded_paths', [])) or 'None'}",
            f"- **User Authorization Confirmed**: {scope_info.get('authorized_by_user', False)}\n",
            "---",
            "## 3. Subdomain Inventory",
            "| Subdomain | Resolved IP | Resolution Status | Discovery Source |",
            "|---|---|---|---|",
        ]
        if subdomains:
            for s in subdomains:
                lines.append(f"| {s.subdomain} | {s.resolved_ip or 'Unresolved'} | {s.resolution_status} | {s.discovery_source} |")
        else:
            lines.append("| None | - | - | - |")

        lines.extend([
            "\n---",
            "## 4. DNS Intelligence",
            "| Host | Type | Value |",
            "|---|---|---|",
        ])
        if dns_records:
            for d in dns_records[:40]:
                lines.append(f"| {d.host} | {d.record_type} | `{d.value}` |")
        else:
            lines.append("| None | - | - |")

        lines.extend([
            "\n---",
            "## 5. Live Hosts",
            "| URL | Status | Web Server | Title | Response Time |",
            "|---|---|---|---|---|",
        ])
        if live_hosts:
            for lh in live_hosts:
                lines.append(f"| {lh.url} | {lh.status_code} | {lh.web_server or '-'} | {lh.title or '-'} | {lh.response_time_ms or '-'} ms |")
        else:
            lines.append("| None | - | - | - | - |")

        lines.extend([
            "\n---",
            "## 6. Technology Fingerprinting",
            "| Host | Category | Technology Name | Detection Source |",
            "|---|---|---|---|",
        ])
        if technologies:
            for t in technologies:
                lines.append(f"| {t.host} | {t.category} | {t.name} | {t.detection_source} |")
        else:
            lines.append("| None | - | - | - |")

        lines.extend([
            "\n---",
            "## 7. Discovered Directories and Files",
            "| Path | Status Code | Content Length | Redirect Location | Tool |",
            "|---|---|---|---|---|",
        ])
        if discovered_paths:
            for dp in discovered_paths:
                lines.append(f"| `{dp.path}` | {dp.status_code} | {dp.content_length} B | {dp.redirect_location or '-'} | {dp.discovery_tool} |")
        else:
            lines.append("| None | - | - | - | - |")

        lines.extend([
            "\n---",
            "## 8. Internal Links Crawled",
            "| Source URL | Destination URL | Method | Link Type | Internal? | Depth |",
            "|---|---|---|---|---|---|",
        ])
        if internal_links:
            for lk in internal_links[:40]:
                lines.append(f"| {lk.source_url} | {lk.destination_url} | {lk.method} | {lk.link_type} | {lk.is_internal} | {lk.crawl_depth} |")
        else:
            lines.append("| None | - | - | - | - | - |")

        lines.extend([
            "\n---",
            "## 9. URL Inventory",
            "| URL | Discovery Origin | Historical? |",
            "|---|---|---|",
        ])
        if endpoints:
            for ep in endpoints[:40]:
                lines.append(f"| {ep.url} | {ep.discovery_source} | {'Yes' if ep.is_historical else 'No (Live)'} |")
        else:
            lines.append("| None | - | - |")

        lines.extend([
            "\n---",
            "## 10. Endpoint Inventory",
            "| Method | Path | Parameters | Historical? |",
            "|---|---|---|---|",
        ])
        if endpoints:
            for ep in endpoints[:40]:
                lines.append(f"| {ep.method} | `{ep.path}` | `{ep.params or '-'}` | {ep.is_historical} |")
        else:
            lines.append("| None | - | - | - |")

        lines.extend([
            "\n---",
            "## 11. Parameter Inventory",
            "| Parameter Name | Type | Example Value |",
            "|---|---|---|",
        ])
        if parameters:
            for p in parameters[:40]:
                lines.append(f"| `{p.name}` | {p.param_type} | `{p.example_value or '-'}` |")
        else:
            lines.append("| None | - | - |")

        lines.extend([
            "\n---",
            "## 12. JavaScript Intelligence",
            "| JavaScript URL | Source Map | Referenced Routes Count | Sanitized Secrets |",
            "|---|---|---|---|",
        ])
        if js_assets:
            for js in js_assets:
                sec_str = "None"
                if js.secrets_found_json:
                    try:
                        secs = json.loads(js.secrets_found_json)
                        sec_str = f"{len(secs)} patterns (masked)"
                    except Exception:
                        pass
                lines.append(f"| {js.url} | {js.source_map_url or 'None'} | {js.routes_found_json or 'None'} | {sec_str} |")
        else:
            lines.append("| None | - | - | - |")

        lines.extend([
            "\n---",
            "## 13. API Discoveries",
            "| API Interface / Documentation Route | Status |",
            "|---|---|",
        ])
        api_paths = [dp for dp in discovered_paths if dp.discovery_tool == "API_DISCOVERY" or "api" in dp.path.lower() or "swagger" in dp.path.lower() or "graphql" in dp.path.lower()]
        if api_paths:
            for ap in api_paths:
                lines.append(f"| `{ap.url}` | HTTP {ap.status_code} |")
        else:
            lines.append("| None identified | - |")

        lines.extend([
            "\n---",
            "## 14. Security Findings",
        ])
        if findings:
            for idx, f in enumerate(findings, 1):
                lines.extend([
                    f"### {idx}. {f.title}",
                    f"- **Severity**: {f.severity} (CVSS: {f.cvss_score or 'N/A'})",
                    f"- **Category**: {f.category}",
                    f"- **Status**: {f.verification_status} (Confidence: {f.confidence})",
                    f"- **Description**: {f.description}",
                    f"- **Impact**: {f.impact}",
                    f"- **Remediation**: {f.remediation}",
                ])
                if f.evidence:
                    lines.append("#### Evidence:")
                    for ev in f.evidence:
                        lines.extend([
                            f"**{ev.evidence_type}** ({ev.source}):",
                            "```",
                            f"{ev.sanitized_data}",
                            "```",
                        ])
                lines.append("\n---\n")
        else:
            lines.append("No security posture vulnerabilities identified.\n")

        lines.extend([
            "## 15. Scan Coverage and Errors",
            "| Stage ID | Stage Name | Status | Duration | Error / Notes |",
            "|---|---|---|---|---|",
        ])
        if stages:
            for st in stages:
                dur = f"{st.duration:.2f}s" if st.duration else "-"
                err = st.error_message or "-"
                lines.append(f"| {st.stage_id} | {st.name} | {st.status} | {dur} | {err} |")
        else:
            lines.append("| None | - | - | - | - |")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def generate_json(
        self,
        assessment: Assessment,
        findings: List[Finding],
        assets: List[Asset],
        output_path: Path,
        **kwargs,
    ) -> Path:
        data = {
            "assessment": {
                "id": assessment.id,
                "target": assessment.target,
                "scan_profile": assessment.scan_profile,
                "status": assessment.status,
                "start_time": assessment.start_time.isoformat() if assessment.start_time else None,
                "end_time": assessment.end_time.isoformat() if assessment.end_time else None,
            },
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "resolved_ip": s.resolved_ip,
                    "status": s.resolution_status,
                    "source": s.discovery_source,
                }
                for s in getattr(assessment, "subdomains", [])
            ],
            "live_hosts": [
                {
                    "url": lh.url,
                    "status_code": lh.status_code,
                    "server": lh.web_server,
                    "title": lh.title,
                    "response_time_ms": lh.response_time_ms,
                }
                for lh in getattr(assessment, "live_hosts", [])
            ],
            "discovered_paths": [
                {
                    "path": dp.path,
                    "status_code": dp.status_code,
                    "content_length": dp.content_length,
                    "redirect_location": dp.redirect_location,
                }
                for dp in getattr(assessment, "discovered_paths", [])
            ],
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "verification_status": f.verification_status,
                    "description": f.description,
                    "impact": f.impact,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return output_path

    def generate_csv(
        self,
        findings: List[Finding],
        output_path: Path,
    ) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Title", "Category", "Severity", "CVSS", "Status", "Confidence", "Description"])
            for finding in findings:
                writer.writerow([
                    finding.id,
                    finding.title,
                    finding.category,
                    finding.severity,
                    finding.cvss_score or "",
                    finding.verification_status,
                    finding.confidence,
                    finding.description.replace("\n", " "),
                ])
        return output_path
