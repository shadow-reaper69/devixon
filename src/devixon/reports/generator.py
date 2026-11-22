"""
Multi-format report generator: HTML, Markdown (Bugcrowd/HackerOne), JSON, and CSV.
"""

import json
import csv
import io
from pathlib import Path
from typing import Dict, Any, List
from jinja2 import Environment, FileSystemLoader, select_autoescape
from devixon.database.models import Assessment, Finding, Asset
from devixon.core.config import load_config
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
    ) -> Path:
        template = self.jinja_env.get_template("report.html")
        critical_count = sum(1 for f in findings if f.severity.upper() == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.upper() == "HIGH")
        medium_count = sum(1 for f in findings if f.severity.upper() in ("MEDIUM", "LOW"))

        html_content = template.render(
            assessment=assessment,
            findings=findings,
            assets=assets,
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
    ) -> Path:
        gen_time = assessment.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if assessment.created_at else "N/A"
        lines = [
            f"# Security Assessment Report: {assessment.target}",
            f"**Assessment ID**: `{assessment.id}`  ",
            f"**Scan Profile**: {assessment.scan_profile}  ",
            f"**Status**: {assessment.status}  ",
            f"**Generated**: {gen_time}  \n",
            "---",
            "## 1. Executive Summary",
            f"Authorized security assessment conducted against target `{assessment.target}` using DEVIXON. All operations strictly conformed to authorized scope profiles.\n",
            f"- **Discovered Assets**: {len(assets)}",
            f"- **Total Findings**: {len(findings)}",
            f"- **Critical / High Issues**: {sum(1 for f in findings if f.severity.upper() in ('CRITICAL', 'HIGH'))}\n",
            "---",
            "## 2. Vulnerability Findings",
        ]

        if not findings:
            lines.append("No security vulnerabilities were identified.\n")
        else:
            for idx, f in enumerate(findings, 1):
                lines.extend([
                    f"### {idx}. {f.title}",
                    f"- **Severity**: {f.severity} (CVSS: {f.cvss_score or 'N/A'})",
                    f"- **Category**: {f.category}",
                    f"- **Validation Status**: {f.verification_status} (Confidence: {f.confidence})",
                    "",
                    "#### Description",
                    f"{f.description}",
                    "",
                    "#### Reproduction Steps",
                    f"{f.reproduction_steps}",
                    "",
                    "#### Impact",
                    f"{f.impact}",
                    "",
                    "#### Remediation",
                    f"{f.remediation}",
                    "",
                ])
                if f.evidence:
                    lines.append("#### Evidence")
                    for ev in f.evidence:
                        lines.extend([
                            f"**{ev.evidence_type}** ({ev.source}):",
                            "```",
                            f"{ev.sanitized_data}",
                            "```",
                        ])
                lines.append("\n---\n")

        lines.extend([
            "## 3. Discovered Asset Inventory",
            "| Hostname | IP Address | Type | Scope | Source |",
            "|---|---|---|---|---|",
        ])
        for a in assets:
            lines.append(f"| {a.hostname} | {a.ip_address or 'Unresolved'} | {a.asset_type} | {a.scope_status} | {a.discovery_source} |")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return output_path

    def generate_json(
        self,
        assessment: Assessment,
        findings: List[Finding],
        assets: List[Asset],
        output_path: Path,
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
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "confidence": f.confidence,
                    "verification_status": f.verification_status,
                    "description": f.description,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "evidence": [
                        {
                            "type": ev.evidence_type,
                            "data": ev.sanitized_data,
                            "source": ev.source,
                        }
                        for ev in f.evidence
                    ],
                }
                for f in findings
            ],
            "assets": [
                {
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "asset_type": a.asset_type,
                    "scope_status": a.scope_status,
                    "discovery_source": a.discovery_source,
                }
                for a in assets
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
