"""
Stage 05: Live Host Discovery.
Probes HTTP and HTTPS ports using httpx (native async library + tool wrapper) with redirect and TLS tracking.
"""

import httpx
from typing import Dict, Any
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage05LiveHosts(BaseStage):
    stage_id = "STAGE_05"
    name = "Live Host Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        timeout = httpx.Timeout(5.0, connect=5.0)

        for host in list(ctx.discovered_subdomains):
            ctx.check_cancelled()
            for proto in ["https", "http"]:
                url = f"{proto}://{host}"
                try:
                    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                        resp = await client.get(url, headers={"User-Agent": "devixon/0.1.0-probe"})
                        ctx.live_hosts[url] = {
                            "host": host,
                            "url": str(resp.url),
                            "status_code": resp.status_code,
                            "server": resp.headers.get("server", ""),
                            "content_type": resp.headers.get("content-type", ""),
                            "content_length": len(resp.content),
                            "title": self._extract_title(resp.text),
                            "headers": dict(resp.headers),
                            "cookies": dict(resp.cookies),
                            "body_sample": resp.text[:1000],
                        }
                        logger.info(f"Live host: {url} -> HTTP {resp.status_code} ({ctx.live_hosts[url]['title']})")
                except Exception:
                    continue

        logger.info(f"Identified {len(ctx.live_hosts)} active HTTP services.")

    def _extract_title(self, html: str) -> str:
        import re
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""
