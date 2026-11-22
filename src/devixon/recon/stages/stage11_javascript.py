"""
Stage 11: JavaScript Intelligence.
Discovers and inspects scoped JavaScript assets for API paths, client routes, source map references,
and sanitized secret patterns. Persists to the JavaScriptAsset table.
"""

import re
from urllib.parse import urlparse, urljoin
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository

SECRET_PATTERNS = [
    ("Generic API Key", re.compile(r"""(?i)(?:api_key|apikey|secret_key|app_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""")),
    ("AWS Access Key", re.compile(r"""(AKIA[0-9A-Z]{16})""")),
    ("Google API Key", re.compile(r"""(AIza[0-9A-Za-z\-_]{35})""")),
    ("Bearer / Token", re.compile(r"""(?i)(?:bearer|jwt|token)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]""")),
]

ROUTE_PATTERN = re.compile(r"""['"](/(?:api|v[0-9]|auth|admin|users|graphql)[a-zA-Z0-9_\-/]*)['"]""")
SOURCEMAP_PATTERN = re.compile(r"""//[#@]\s*sourceMappingURL=([^\s]+)""")


class Stage11JavaScriptIntelligence(BaseStage):
    stage_id = "STAGE_11"
    name = "JavaScript Intelligence"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        # Collect scoped JS URLs
        js_urls = [u for u in ctx.discovered_urls if u.endswith(".js") or ".js?" in u]
        logger.info(f"Analyzing {len(js_urls)} scoped JavaScript files...")

        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                for js_url in js_urls[:20]:  # Controlled bounds
                    ctx.check_cancelled()
                    try:
                        resp = await client.get(js_url)
                        if resp.status_code != 200:
                            continue
                        text = resp.text
                        host = urlparse(js_url).hostname or ctx.target

                        # 1. Routes & API paths
                        routes = list(set(ROUTE_PATTERN.findall(text)))
                        for r in routes:
                            ctx.api_endpoints.append(r)

                        # 2. Source map references
                        sm_match = SOURCEMAP_PATTERN.search(text)
                        source_map_url = None
                        if sm_match:
                            sm_rel = sm_match.group(1).strip()
                            source_map_url = urljoin(js_url, sm_rel)

                        # 3. Secret indicators (Masked for safety!)
                        masked_secrets = []
                        for sec_type, pat in SECRET_PATTERNS:
                            matches = pat.findall(text)
                            for m in matches:
                                masked = m[:4] + "*" * (len(m) - 6) + m[-2:] if len(m) > 6 else "***"
                                masked_secrets.append({"type": sec_type, "masked": masked})
                                ctx.js_findings.append({
                                    "file": js_url,
                                    "type": sec_type,
                                    "masked_value": masked,
                                })

                        # Persist JavaScript asset record
                        repo.add_js_asset(
                            assessment_id=ctx.assessment_id,
                            url=js_url,
                            host=host,
                            endpoints_found=routes,
                            routes_found=routes,
                            secrets_found=masked_secrets,
                            source_map_url=source_map_url,
                        )

                        ctx.js_assets.append({
                            "url": js_url,
                            "host": host,
                            "routes": routes,
                            "source_map": source_map_url,
                            "secrets": masked_secrets,
                        })

                    except Exception:
                        continue

            logger.info(f"JavaScript intelligence completed. Recorded {len(ctx.js_assets)} JS assets.")
        finally:
            session.close()
