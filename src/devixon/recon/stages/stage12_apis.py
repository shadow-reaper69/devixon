"""
Stage 12: API Reconnaissance.
Identifies Swagger UI, OpenAPI schemas, GraphQL endpoints, and REST routing.
"""

import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger

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
        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
            for base_url in list(ctx.live_hosts.keys())[:5]:
                ctx.check_cancelled()
                for path in COMMON_API_PATHS:
                    target_url = base_url.rstrip("/") + path
                    try:
                        resp = await client.get(target_url)
                        if resp.status_code == 200 and len(resp.content) > 20:
                            content_lower = resp.text.lower()
                            if any(k in content_lower for k in ["swagger", "openapi", "graphql", "paths"]):
                                ctx.api_endpoints.append(target_url)
                                logger.info(f"Discovered API Documentation / Interface: {target_url}")
                    except Exception:
                        continue

        logger.info(f"API reconnaissance completed. Found {len(ctx.api_endpoints)} candidate API routes.")
