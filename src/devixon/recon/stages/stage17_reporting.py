"""
Stage 17: Final Report Generation.
Generates comprehensive HTML, Markdown, JSON, and CSV reports containing all 15 reconnaissance intelligence sections.
"""

from pathlib import Path
from devixon.recon.base import BaseStage, ScanContext
from devixon.database.session import get_session
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
from devixon.reports.generator import ReportGenerator
from devixon.core.config import load_config
from devixon.core.logger import logger


class Stage17ReportGeneration(BaseStage):
    stage_id = "STAGE_17"
    name = "Final Report Generation"

    async def execute(self, ctx: ScanContext) -> None:
        cfg = load_config()
        reports_dir = Path(cfg.output.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)

        session = get_session()
        try:
            assessment = session.query(Assessment).filter(Assessment.id == ctx.assessment_id).first()
            if not assessment:
                return

            findings = session.query(Finding).filter(Finding.assessment_id == ctx.assessment_id).all()
            assets = session.query(Asset).filter(Asset.assessment_id == ctx.assessment_id).all()
            subdomains = session.query(Subdomain).filter(Subdomain.assessment_id == ctx.assessment_id).all()
            dns_records = session.query(DNSRecord).filter(DNSRecord.assessment_id == ctx.assessment_id).all()
            live_hosts = session.query(LiveHost).filter(LiveHost.assessment_id == ctx.assessment_id).all()
            discovered_paths = session.query(DiscoveredPath).filter(DiscoveredPath.assessment_id == ctx.assessment_id).all()
            internal_links = session.query(InternalLink).filter(InternalLink.assessment_id == ctx.assessment_id).all()
            endpoints = session.query(Endpoint).filter(Endpoint.assessment_id == ctx.assessment_id).all()
            parameters = session.query(Parameter).filter(Parameter.assessment_id == ctx.assessment_id).all()
            js_assets = session.query(JavaScriptAsset).filter(JavaScriptAsset.assessment_id == ctx.assessment_id).all()
            technologies = session.query(Technology).filter(Technology.assessment_id == ctx.assessment_id).all()
            stages = session.query(ScanStage).filter(ScanStage.assessment_id == ctx.assessment_id).all()

            generator = ReportGenerator()
            base_filename = f"devixon_report_{ctx.target.replace('.', '_')}_{ctx.assessment_id[:8]}"

            html_file = reports_dir / f"{base_filename}.html"
            md_file = reports_dir / f"{base_filename}.md"
            json_file = reports_dir / f"{base_filename}.json"
            csv_file = reports_dir / f"{base_filename}.csv"

            generator.generate_html(
                assessment=assessment,
                findings=findings,
                assets=assets,
                output_path=html_file,
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
            )

            generator.generate_markdown(
                assessment=assessment,
                findings=findings,
                assets=assets,
                output_path=md_file,
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
            )

            generator.generate_json(assessment, findings, assets, json_file)
            generator.generate_csv(findings, csv_file)

            logger.info("Generated assessment reports:")
            logger.info(f"  - HTML: {html_file}")
            logger.info(f"  - Markdown: {md_file}")
            logger.info(f"  - JSON: {json_file}")
            logger.info(f"  - CSV: {csv_file}")

        finally:
            session.close()
