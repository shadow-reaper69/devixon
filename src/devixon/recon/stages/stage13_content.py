"""
Stage 13: Content Discovery.
Safe probing of standard disclosure files and routes with strict request bounds and non-destructive checks.
"""

import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger

SAFE_DISCLOSURE_PATHS = [
    "/robots.txt",
    "/.well-known/security.txt",
    "/security.txt",
    "/sitemap.xml",
    "/.git/HEAD",
    "/.env",
]


class Stage13ContentDiscovery(BaseStage):
    stage_id = "STAGE_13"
    name = "Content & Sensitive Route Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=False) as client:
            for base_url in list(ctx.live_hosts.keys())[:5]:
                ctx.check_cancelled()
                for path in SAFE_DISCLOSURE_PATHS:
                    target_url = base_url.rstrip("/") + path
                    try:
                        resp = await client.get(target_url)
                        if resp.status_code == 200 and len(resp.content) > 0:
                            # Evaluate for sensitive disclosure
                            if path == "/.git/HEAD" and "ref: refs/" in resp.text:
                                ctx.posture_findings.append({
                                    "title": "Publicly Accessible .git Directory",
                                    "category": "Security Misconfiguration",
                                    "severity": "HIGH",
                                    "url": target_url,
                                    "evidence": f"HTTP 200: {resp.text[:100]}",
                                })
                            elif path == "/.env" and any(k in resp.text for k in ["DB_", "APP_", "SECRET"]):
                                ctx.posture_findings.append({
                                    "title": "Publicly Accessible .env Environment File",
                                    "category": "Security Misconfiguration",
                                    "severity": "CRITICAL",
                                    "url": target_url,
                                    "evidence": "Config directives matched",
                                })
                            elif path in ("/robots.txt", "/sitemap.xml"):
                                ctx.discovered_urls.add(target_url)
                    except Exception:
                        continue

        logger.info(f"Safe content discovery completed.")
