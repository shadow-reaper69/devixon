"""
Stage 10: Endpoint & Parameter Extraction.
Extracts paths, query parameters, HTTP methods, content types, and persists Endpoint and Parameter records.
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
            for url in list(ctx.discovered_urls):
                ctx.check_cancelled()
                parsed = urlparse(url)
                # Verify scope policy before persisting endpoint
                is_in, _ = ctx.scope_profile.is_in_scope(url, path=parsed.path, port=parsed.port)
                if not is_in:
                    continue

                host = parsed.hostname or ctx.target_model.hostname

                # Find asset if present
                asset = session.query(Asset).filter(
                    Asset.assessment_id == ctx.assessment_id,
                    (Asset.hostname == host) | (Asset.hostname == ctx.target_model.hostname)
                ).first()
                asset_id = asset.id if asset else None

                # Query parameters extraction
                params_dict = parse_qs(parsed.query)
                params_str = ",".join(params_dict.keys()) if params_dict else None

                # Check if it was discovered solely from historical archives
                is_historical = url not in ctx.live_hosts

                ep = repo.add_endpoint(
                    assessment_id=ctx.assessment_id,
                    asset_id=asset_id,
                    url=url,
                    path=parsed.path or "/",
                    method="GET",
                    params=params_str,
                    is_historical=is_historical,
                    discovery_source="CRAWLER" if not is_historical else "GAU_WAYBACK",
                )

                # Persist individual parameters
                if params_dict:
                    for p_name, p_vals in params_dict.items():
                        example_val = p_vals[0] if p_vals else ""
                        param = repo.add_parameter(
                            assessment_id=ctx.assessment_id,
                            endpoint_id=ep.id,
                            name=p_name,
                            param_type="query",
                            example_value=example_val,
                        )
                        ctx.parameters.append({
                            "endpoint_url": url,
                            "name": p_name,
                            "type": "query",
                            "example": example_val,
                        })

                ctx.endpoints.append({
                    "id": ep.id,
                    "url": url,
                    "path": parsed.path or "/",
                    "params": params_str,
                    "is_historical": is_historical,
                })

            logger.info(f"Persisted {len(ctx.endpoints)} endpoints and {len(ctx.parameters)} parameters to database.")
        finally:
            session.close()
