"""
Stage 06: Service Discovery.
Safe port checks for common web/infrastructure ports using native async socket probes + optional nmap wrapper.
Distinguishes open TCP ports from confirmed HTTP/HTTPS services and registers confirmed live hosts.
"""

import asyncio
import shutil
from typing import Optional
from urllib.parse import urlsplit
import httpx
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
            # Determine ports to probe based on scope and target model
            if ctx.scope_profile.allowed_ports:
                ports_to_probe = ctx.scope_profile.allowed_ports
            elif ctx.target_model.port is not None and ctx.target_model.target_type == "URL":
                ports_to_probe = [ctx.target_model.port]
            else:
                ports_to_probe = SAFE_PORTS

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

                for port in ports_to_probe:
                    # Enforce port scope policy before probing
                    is_allowed, reason = ctx.scope_profile.is_in_scope(domain, port=port)
                    if not is_allowed:
                        logger.debug(f"Skipping port {port} on {domain}: {reason}")
                        continue

                    is_open = await self._probe_port(domain, port)
                    if is_open:
                        open_ports.append(port)
                        # Distinguish open TCP port from confirmed HTTP/HTTPS service
                        confirmed_proto = await self._probe_http_service(domain, port, ctx)
                        service_name = confirmed_proto if confirmed_proto else "tcp"

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

    async def _probe_http_service(self, host: str, port: int, ctx: ScanContext) -> Optional[str]:
        """Probes an open TCP port to determine if it speaks HTTP or HTTPS."""
        schemes = ["http", "https"] if port not in (443, 8443) else ["https", "http"]
        if ctx.target_model.scheme and port == ctx.target_model.port:
            schemes = [ctx.target_model.scheme]

        timeout = httpx.Timeout(3.0, connect=2.0)
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            for proto in schemes:
                base_path = ctx.target_model.base_path if (port == ctx.target_model.port or ctx.target_model.target_type == "URL") else "/"
                if (proto == "http" and port != 80) or (proto == "https" and port != 443):
                    url = f"{proto}://{host}:{port}{base_path}"
                else:
                    url = f"{proto}://{host}{base_path}"

                # Enforce scope check before probing
                is_in, _ = ctx.scope_profile.is_in_scope(url, path=base_path, port=port)
                if not is_in:
                    continue

                try:
                    resp = await client.get(url, headers={"User-Agent": "devixon/0.2.0-probe"})
                    if resp.status_code:
                        service_identity = f"{proto}://{host}:{port}"
                        if url not in ctx.live_hosts:
                            session = get_session()
                            repo = AssessmentRepository(session)
                            try:
                                title = ""
                                m = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                                if m:
                                    title = m.group(1).strip()

                                lh = repo.add_live_host(
                                    assessment_id=ctx.assessment_id,
                                    url=url,
                                    host=service_identity,
                                    status_code=resp.status_code,
                                    title=title,
                                    web_server=resp.headers.get("server", ""),
                                    content_type=resp.headers.get("content-type", ""),
                                    response_time_ms=0.0,
                                )
                                ctx.live_hosts[url] = {
                                    "id": lh.id,
                                    "host": service_identity,
                                    "url": url,
                                    "status_code": resp.status_code,
                                    "server": resp.headers.get("server", ""),
                                    "content_type": resp.headers.get("content-type", ""),
                                    "content_length": len(resp.content),
                                    "title": title,
                                    "headers": dict(resp.headers),
                                    "cookies": dict(resp.cookies),
                                }
                                logger.info(f"Confirmed web service on {host}:{port} -> {proto.upper()} (HTTP {resp.status_code})")
                            finally:
                                session.close()
                        return proto
                except Exception as e:
                    logger.debug(f"Port {port} on {host} HTTP probe failed ({proto}): {type(e).__name__} - {e}")
        return None
