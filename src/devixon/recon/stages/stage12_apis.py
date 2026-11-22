"""
Stage 12: API Reconnaissance.
Identifies Swagger UI, OpenAPI documentation, GraphQL endpoints, and REST route patterns.
"""

from urllib.parse import urlparse
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository

COMMON_API_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/api-docs",
    "/graphql",
    "/graphiql",
]


class Stage12APISurvey(BaseStage):
    stage_id = "STAGE_12"
    name = "API Reconnaissance"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        try:
            async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
                for base_url in list(ctx.live_hosts.keys())[:5]:
                    ctx.check_cancelled()
                    host = urlparse(base_url).hostname or ctx.target

                    for path in COMMON_API_PATHS:
                        target_url = base_url.rstrip("/") + path
                        try:
                            resp = await client.get(target_url)
                            if resp.status_code == 200 and len(resp.content) > 20:
                                content_lower = resp.text.lower()
                                if any(k in content_lower for k in ["swagger", "openapi", "graphql", "paths", "schema"]):
                                    ctx.api_endpoints.append(target_url)

                                    repo.add_discovered_path(
                                        assessment_id=ctx.assessment_id,
                                        host=host,
                                        url=target_url,
                                        path=path,
                                        status_code=resp.status_code,
                                        content_length=len(resp.content),
                                        discovery_tool="API_DISCOVERY",
                                    )

                                    repo.add_endpoint(
                                        assessment_id=ctx.assessment_id,
                                        url=target_url,
                                        path=path,
                                        method="GET",
                                        discovery_source="API_DISCOVERY",
                                    )

                                    logger.info(f"Discovered API Schema/Interface: {target_url}")
                        except Exception:
                            continue

            logger.info(f"API reconnaissance completed. Found {len(ctx.api_endpoints)} candidate API routes.")
        finally:
            session.close()
