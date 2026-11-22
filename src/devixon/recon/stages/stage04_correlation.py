"""
Stage 04: Asset Correlation and Database Inventory.
Correlates hostnames with resolved IPs and persists in database.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository
from devixon.core.logger import logger


class Stage04AssetCorrelation(BaseStage):
    stage_id = "STAGE_04"
    name = "Asset Correlation & Inventory"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        try:
            for domain in ctx.discovered_subdomains:
                ctx.check_cancelled()
                dns_info = ctx.dns_records.get(domain, {})
                a_records = dns_info.get("A", [])
                primary_ip = a_records[0] if a_records else None

                in_scope, _ = ctx.scope_profile.is_in_scope(domain)
                scope_status = "IN_SCOPE" if in_scope else "OUT_OF_SCOPE"
                asset_type = "DOMAIN" if domain == ctx.target else "SUBDOMAIN"

                repo.add_asset(
                    assessment_id=ctx.assessment_id,
                    hostname=domain,
                    ip_address=primary_ip,
                    asset_type=asset_type,
                    scope_status=scope_status,
                    discovery_source="RECON_STAGE_01_03",
                    tags=["dns_resolved"] if primary_ip else ["unresolved"],
                )
        finally:
            session.close()

        logger.info(f"Correlated and saved {len(ctx.discovered_subdomains)} assets to database.")
