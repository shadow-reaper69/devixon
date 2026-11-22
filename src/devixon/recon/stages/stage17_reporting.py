"""
Stage 17: Final Report Generation.
Generates HTML, Markdown, JSON, and CSV reports for the assessment.
"""

from pathlib import Path
from devixon.recon.base import BaseStage, ScanContext
from devixon.database.session import get_session
from devixon.database.models import Assessment, Finding, Asset
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

            generator = ReportGenerator()
            base_filename = f"devixon_report_{ctx.target.replace('.', '_')}_{ctx.assessment_id[:8]}"

            html_file = reports_dir / f"{base_filename}.html"
            md_file = reports_dir / f"{base_filename}.md"
            json_file = reports_dir / f"{base_filename}.json"
            csv_file = reports_dir / f"{base_filename}.csv"

            generator.generate_html(assessment, findings, assets, html_file)
            generator.generate_markdown(assessment, findings, assets, md_file)
            generator.generate_json(assessment, findings, assets, json_file)
            generator.generate_csv(findings, csv_file)

            logger.info(f"Generated assessment reports:")
            logger.info(f"  - HTML: {html_file}")
            logger.info(f"  - Markdown: {md_file}")
            logger.info(f"  - JSON: {json_file}")
            logger.info(f"  - CSV: {csv_file}")

        finally:
            session.close()
