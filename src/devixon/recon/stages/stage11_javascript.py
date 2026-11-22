"""
Stage 11: JavaScript Intelligence.
Analyzes scoped JS scripts for API routes, endpoints, and credentials (with strict masking and non-exploitation).
"""

import re
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger

SECRET_PATTERNS = [
    ("Generic API Key", re.compile(r"""(?i)(?:api_key|apikey|secret_key|app_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""")),
    ("AWS Access Key", re.compile(r"""(AKIA[0-9A-Z]{16})""")),
    ("Google API Key", re.compile(r"""(AIza[0-9A-Za-z\-_]{35})""")),
]

ROUTE_PATTERN = re.compile(r"""['"](/(?:api|v[0-9]|auth|admin|users|graphql)[a-zA-Z0-9_\-/]*)['"]""")


class Stage11JavaScriptIntelligence(BaseStage):
    stage_id = "STAGE_11"
    name = "JavaScript Intelligence"

    async def execute(self, ctx: ScanContext) -> None:
        js_urls = [u for u in ctx.discovered_urls if u.endswith(".js")]
        logger.info(f"Analyzing {len(js_urls)} scoped JavaScript files...")

        async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
            for js_url in js_urls[:15]:  # Safety bound
                ctx.check_cancelled()
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue
                    text = resp.text

                    # 1. Route extraction
                    routes = set(ROUTE_PATTERN.findall(text))
                    for r in routes:
                        ctx.api_endpoints.append(r)

                    # 2. Secret indicators (Masking immediately!)
                    for sec_type, pat in SECRET_PATTERNS:
                        matches = pat.findall(text)
                        for m in matches:
                            masked = m[:4] + "*" * (len(m) - 6) + m[-2:] if len(m) > 6 else "***"
                            ctx.js_findings.append({
                                "file": js_url,
                                "type": sec_type,
                                "masked_value": masked,
                            })
                            logger.warning(f"Potential secret pattern ({sec_type}) in {js_url}: {masked}")
                except Exception:
                    continue

        logger.info(f"JS intelligence identified {len(ctx.api_endpoints)} routes and {len(ctx.js_findings)} key indicators.")
