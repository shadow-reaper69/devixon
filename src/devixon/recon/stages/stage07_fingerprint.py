"""
Stage 07: Technology Fingerprinting.
Extracts and persists Technology records to the database with category, confidence, and detection source.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository


class Stage07TechnologyFingerprint(BaseStage):
    stage_id = "STAGE_07"
    name = "Technology Fingerprinting"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        try:
            for url, data in ctx.live_hosts.items():
                ctx.check_cancelled()
                host = data.get("host", url)
                techs = data.get("technologies", [])

                for item in techs:
                    if ":" in item:
                        cat, name = item.split(":", 1)
                    else:
                        cat, name = "Software", item

                    repo.add_technology(
                        assessment_id=ctx.assessment_id,
                        host=host,
                        name=name,
                        category=cat,
                        confidence="CONFIRMED",
                        detection_source="HTTP_PROBE",
                    )

                if host not in ctx.technologies:
                    ctx.technologies[host] = []
                ctx.technologies[host].extend(techs)

            logger.info("Technology fingerprinting completed and persisted to database.")
        finally:
            session.close()
