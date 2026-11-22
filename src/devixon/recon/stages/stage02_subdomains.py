"""
Stage 02: Subdomain Discovery.
Wraps Subfinder / Amass if installed, or gracefully falls back to native OSINT results.
"""

import shutil
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.runner import run_subprocess
from devixon.core.logger import logger


class Stage02SubdomainDiscovery(BaseStage):
    stage_id = "STAGE_02"
    name = "Subdomain Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        target = ctx.target
        subfinder_bin = shutil.which("subfinder")

        if subfinder_bin:
            logger.info("External tool 'subfinder' detected. Running active tool integration...")
            try:
                cmd = [subfinder_bin, "-d", target, "-silent", "-all"]
                code, stdout, stderr = await run_subprocess(cmd, timeout=60.0)
                if code == 0:
                    for line in stdout.splitlines():
                        sub = line.strip().lower()
                        if sub:
                            in_scope, _ = ctx.scope_profile.is_in_scope(sub)
                            if in_scope:
                                ctx.discovered_subdomains.add(sub)
            except Exception as e:
                logger.warning(f"Subfinder execution encountered notice: {e}")
        else:
            logger.info("[SKIP] 'subfinder' binary not found on PATH. Using native OSINT subdomain inventory.")

        logger.info(f"Subdomain discovery complete. Total subdomains in scope: {len(ctx.discovered_subdomains)}")
