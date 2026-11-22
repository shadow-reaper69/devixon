"""
Stage 03: DNS Intelligence.
Resolves A, AAAA, CNAME, MX, TXT records using dnspython with graceful timeout handling.
"""

import asyncio
import dns.resolver
from typing import Dict, List
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage03DNSIntelligence(BaseStage):
    stage_id = "STAGE_03"
    name = "DNS Intelligence"

    async def execute(self, ctx: ScanContext) -> None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        record_types = ["A", "AAAA", "CNAME", "MX", "TXT"]

        for domain in list(ctx.discovered_subdomains):
            ctx.check_cancelled()
            records_map: Dict[str, List[str]] = {}

            for r_type in record_types:
                try:
                    # Run in executor to prevent blocking async loop
                    loop = asyncio.get_running_loop()
                    answers = await loop.run_in_executor(
                        None,
                        lambda d=domain, t=r_type: resolver.resolve(d, t)
                    )
                    records_map[r_type] = [str(r.to_text()).strip('"') for r in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                    records_map[r_type] = []

            ctx.dns_records[domain] = records_map

        logger.info(f"DNS intelligence completed for {len(ctx.dns_records)} domains.")
