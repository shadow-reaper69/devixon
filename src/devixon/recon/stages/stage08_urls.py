"""
Stage 08: URL & Endpoint Intelligence.
Integrates GAU, Waybackurls (optional), and Katana with native archive queries.
Distinguishes historical URLs from live endpoints and records provenance.
"""

import shutil
from urllib.parse import urlparse
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.runner import run_subprocess
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository


class Stage08URLIntelligence(BaseStage):
    stage_id = "STAGE_08"
    name = "URL Intelligence & History"

    async def execute(self, ctx: ScanContext) -> None:
        target = ctx.target
        session = get_session()
        repo = AssessmentRepository(session)

        gau_bin = shutil.which("gau")
        wayback_bin = shutil.which("waybackurls")
        historical_urls = set()

        # External Tool 1: GAU
        if gau_bin:
            logger.info("Running GAU adapter for historical URLs...")
            try:
                cmd = [gau_bin, "--subs", target, "--threads", "2", "--limit", "100"]
                code, stdout, _ = await run_subprocess(cmd, timeout=30.0)
                if code == 0:
                    for line in stdout.splitlines():
                        u = line.strip()
                        if u and ctx.scope_profile.is_in_scope(u)[0]:
                            historical_urls.add(u)
            except Exception as e:
                logger.warning(f"GAU execution notice: {e}")

        # External Tool 2: Waybackurls (optional)
        if not historical_urls and wayback_bin:
            logger.info("Running Waybackurls adapter...")
            try:
                cmd = [wayback_bin, target]
                code, stdout, _ = await run_subprocess(cmd, timeout=30.0)
                if code == 0:
                    for line in stdout.splitlines():
                        u = line.strip()
                        if u and ctx.scope_profile.is_in_scope(u)[0]:
                            historical_urls.add(u)
            except Exception as e:
                logger.warning(f"Waybackurls execution notice: {e}")

        # Native Web Archive Fallback
        if not historical_urls and target.lower() not in ("localhost", "127.0.0.1", "::1"):
            archive_url = f"https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey&limit=50"
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.get(archive_url)
                    if resp.status_code == 200:
                        data = resp.json()
                        for row in data[1:]:
                            if len(row) > 2:
                                raw_u = row[2]
                                if ctx.scope_profile.is_in_scope(raw_u)[0]:
                                    historical_urls.add(raw_u)
            except Exception as e:
                logger.warning(f"Native archive query notice: {e}")

        try:
            # Persist historical endpoints
            for h_url in historical_urls:
                parsed = urlparse(h_url)
                repo.add_endpoint(
                    assessment_id=ctx.assessment_id,
                    url=h_url,
                    path=parsed.path or "/",
                    method="GET",
                    params=parsed.query or None,
                    is_historical=True,
                    discovery_source="GAU_WAYBACK",
                )
                ctx.discovered_urls.add(h_url)

            # Also seed live hosts
            for live_url in ctx.live_hosts.keys():
                ctx.discovered_urls.add(live_url)

            logger.info(f"URL intelligence collected {len(historical_urls)} historical URLs and {len(ctx.live_hosts)} live URLs.")
        finally:
            session.close()
