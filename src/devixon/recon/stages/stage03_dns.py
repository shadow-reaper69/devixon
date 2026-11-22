"""
Stage 03: DNS Intelligence.
Resolves A, AAAA, CNAME, MX, TXT, and NS records using dnspython and persists DNSRecord entries.
"""

import asyncio
import dns.resolver
from typing import Dict, List
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository


class Stage03DNSIntelligence(BaseStage):
    stage_id = "STAGE_03"
    name = "DNS Intelligence"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0

        record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]

        try:
            for domain in list(ctx.discovered_subdomains):
                ctx.check_cancelled()

                # For localhost / IP targets, skip external DNS queries
                if domain.lower() in ("localhost", "127.0.0.1", "::1"):
                    repo.add_dns_record(
                        assessment_id=ctx.assessment_id,
                        host=domain,
                        record_type="A",
                        value="127.0.0.1",
                    )
                    ctx.dns_records[domain] = {"A": ["127.0.0.1"]}
                    continue

                records_map: Dict[str, List[str]] = {}
                primary_ip = None

                for r_type in record_types:
                    try:
                        loop = asyncio.get_running_loop()
                        answers = await loop.run_in_executor(
                            None,
                            lambda d=domain, t=r_type: resolver.resolve(d, t)
                        )
                        values = [str(r.to_text()).strip('"') for r in answers]
                        records_map[r_type] = values

                        for val in values:
                            repo.add_dns_record(
                                assessment_id=ctx.assessment_id,
                                host=domain,
                                record_type=r_type,
                                value=val,
                            )
                            if r_type == "A" and not primary_ip:
                                primary_ip = val

                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                        records_map[r_type] = []

                ctx.dns_records[domain] = records_map
                if primary_ip:
                    repo.add_subdomain(
                        assessment_id=ctx.assessment_id,
                        subdomain=domain,
                        resolved_ip=primary_ip,
                        resolution_status="RESOLVED",
                        dns_records=records_map,
                    )

            logger.info(f"DNS intelligence persisted for {len(ctx.dns_records)} domains.")
        finally:
            session.close()
