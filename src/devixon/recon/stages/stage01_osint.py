"""
Stage 01: Passive OSINT.
Queries Certificate Transparency (crt.sh) and public passive sources with rate limiting.
"""

import httpx
from typing import Set
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage01PassiveOSINT(BaseStage):
    stage_id = "STAGE_01"
    name = "Passive OSINT Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        target = ctx.target
        found_subdomains: Set[str] = set()

        # Query crt.sh Certificate Transparency
        url = f"https://crt.sh/?q=%.{target}&output=json"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(url, headers={"User-Agent": "devixon/0.1.0-recon"})
                if res.status_code == 200:
                    entries = res.json()
                    for item in entries:
                        name_value = item.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub.startswith("*."):
                                sub = sub[2:]
                            if sub and sub.endswith(target):
                                in_scope, _ = ctx.scope_profile.is_in_scope(sub)
                                if in_scope:
                                    found_subdomains.add(sub)
        except Exception as e:
            logger.warning(f"Passive crt.sh query notice: {e}")

        # Add target itself
        found_subdomains.add(target)
        ctx.discovered_subdomains.update(found_subdomains)
        logger.info(f"Passive OSINT identified {len(found_subdomains)} subdomains for {target}")
