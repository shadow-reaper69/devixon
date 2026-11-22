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

        base_urls = []
        if ctx.target_model.target_type == "URL":
            base_urls.append(ctx.target_model.canonical_url)
        for u in list(ctx.live_hosts.keys()):
            if u not in base_urls:
                base_urls.append(u)
        base_urls = base_urls[:5]

        try:
            async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
                for base_url in base_urls:
                    ctx.check_cancelled()
                    host = ctx.target_model.service_identity if ctx.target_model.target_type == "URL" else (urlparse(base_url).hostname or ctx.target_model.hostname)
                    app_base_path = ctx.target_model.base_path.rstrip("/") if ctx.target_model.target_type == "URL" else ""

                    for path in COMMON_API_PATHS:
                        effective_path = f"{app_base_path}{path}" if app_base_path else path
                        clean_base = base_url.rstrip("/")
                        if app_base_path and clean_base.endswith(app_base_path):
                            target_url = clean_base + path
                        else:
                            target_url = clean_base + effective_path

                        p_target = urlparse(target_url)
                        is_allowed, _ = ctx.scope_profile.is_in_scope(target_url, path=p_target.path, port=p_target.port)
                        if not is_allowed:
                            continue

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
                                        path=p_target.path,
                                        status_code=resp.status_code,
                                        content_length=len(resp.content),
                                        discovery_tool="API_DISCOVERY",
                                    )

                                    repo.add_endpoint(
                                        assessment_id=ctx.assessment_id,
                                        url=target_url,
                                        path=p_target.path,
                                        method="GET",
                                        discovery_source="API_DISCOVERY",
                                    )

                                    logger.info(f"Discovered API Schema/Interface: {target_url}")
                        except Exception:
                            continue

            logger.info(f"API reconnaissance completed. Found {len(ctx.api_endpoints)} candidate API routes.")
        finally:
            session.close()
