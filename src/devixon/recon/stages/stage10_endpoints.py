"""
Stage 10: Endpoint Extraction.
Extracts paths, query parameters, methods, and content types, saving to DB.
"""

from urllib.parse import urlparse, parse_qs
from devixon.recon.base import BaseStage, ScanContext
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository
from devixon.database.models import Asset
from devixon.core.logger import logger


class Stage10EndpointExtraction(BaseStage):
    stage_id = "STAGE_10"
    name = "Endpoint & Parameter Extraction"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        try:
            for url in ctx.discovered_urls:
                ctx.check_cancelled()
                parsed = urlparse(url)
                host = parsed.hostname or ctx.target

                # Find asset
                asset = session.query(Asset).filter(
                    Asset.assessment_id == ctx.assessment_id,
                    Asset.hostname == host
                ).first()
                if not asset:
                    continue

                params_dict = parse_qs(parsed.query)
                params_str = ",".join(params_dict.keys()) if params_dict else None

                ep = repo.add_endpoint(
                    asset_id=asset.id,
                    url=url,
                    path=parsed.path or "/",
                    method="GET",
                    params=params_str,
                    discovery_source="CRAWLER",
                )
                ctx.endpoints.append({
                    "id": ep.id,
                    "asset_id": asset.id,
                    "url": url,
                    "path": parsed.path or "/",
                    "params": params_str,
                })

        finally:
            session.close()

        logger.info(f"Extracted and saved {len(ctx.endpoints)} unique endpoints.")
