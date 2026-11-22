"""
Stage 16: AI Analysis.
Optional AI-assisted evaluation of attack surface and findings with prompt isolation and offline fallback.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.ai.client import AIAnalystClient
from devixon.database.session import get_session
from devixon.database.models import Finding
from devixon.core.logger import logger


class Stage16AIAnalysis(BaseStage):
    stage_id = "STAGE_16"
    name = "AI Security Analysis"

    async def execute(self, ctx: ScanContext) -> None:
        ai_client = AIAnalystClient()
        if not ai_client.is_available():
            logger.info("AI analysis skipped (AI is disabled or API key is not configured).")
            return

        session = get_session()
        try:
            findings = session.query(Finding).filter(Finding.assessment_id == ctx.assessment_id).all()
            for f in findings:
                ctx.check_cancelled()
                try:
                    ev_text = "\n".join([ev.sanitized_data for ev in f.evidence]) or f.description
                    analysis = await ai_client.analyze_finding(
                        title=f.title,
                        category=f.category,
                        evidence_text=ev_text,
                        asset_info=ctx.target,
                    )
                    # Update remediation if AI provides a superior context-aware fix
                    if analysis.remediation_recommendation:
                        f.remediation = f"{f.remediation}\n\n[AI Remediation Guidance]: {analysis.remediation_recommendation}"
                        session.commit()
                except Exception as e:
                    logger.warning(f"AI analysis error on finding '{f.title}': {e}")
        finally:
            session.close()

        logger.info("AI analysis phase completed.")
