"""
Stage 06: Service Discovery.
Safe port checks for common web/infrastructure ports using native async socket probes + optional nmap wrapper.
"""

import asyncio
import shutil
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository
from devixon.database.models import Asset

# Safe standard web & proxy ports
SAFE_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]


class Stage06ServiceDiscovery(BaseStage):
    stage_id = "STAGE_06"
    name = "Service Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        try:
            for domain in list(ctx.discovered_subdomains):
                ctx.check_cancelled()
                open_ports = []

                # Find asset in DB
                asset = session.query(Asset).filter(
                    Asset.assessment_id == ctx.assessment_id,
                    Asset.hostname == domain
                ).first()
                if not asset:
                    continue

                for port in SAFE_PORTS:
                    is_open = await self._probe_port(domain, port)
                    if is_open:
                        open_ports.append(port)
                        proto = "https" if port in (443, 8443) else "http"
                        service_name = "https" if proto == "https" else "http"
                        repo.add_service(
                            asset_id=asset.id,
                            port=port,
                            protocol="tcp",
                            service_name=service_name,
                            confidence="CONFIRMED",
                        )

                if open_ports:
                    ctx.open_ports[domain] = open_ports
                    logger.info(f"Host {domain} open ports: {open_ports}")

        finally:
            session.close()

    async def _probe_port(self, host: str, port: int, timeout: float = 1.5) -> bool:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
