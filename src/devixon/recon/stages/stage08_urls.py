"""
Stage 08: URL Intelligence.
Retrieves historical and known URLs from web archives and native URL builders.
"""

import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage08URLIntelligence(BaseStage):
    stage_id = "STAGE_08"
    name = "URL Intelligence & History"

    async def execute(self, ctx: ScanContext) -> None:
        target = ctx.target
        archive_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey&limit=50"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(archive_url)
                if resp.status_code == 200:
                    data = resp.json()
                    # First row is headers: ["urlkey", "timestamp", "original", ...]
                    for row in data[1:]:
                        if len(row) > 2:
                            raw_u = row[2]
                            in_scope, _ = ctx.scope_profile.is_in_scope(raw_u)
                            if in_scope:
                                ctx.discovered_urls.add(raw_u)
        except Exception as e:
            logger.warning(f"Archive URL lookup notice: {e}")

        # Also add live host URLs
        ctx.discovered_urls.update(ctx.live_hosts.keys())
        logger.info(f"URL intelligence gathered {len(ctx.discovered_urls)} scoped URLs.")
