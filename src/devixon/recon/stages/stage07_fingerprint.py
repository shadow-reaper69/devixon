"""
Stage 07: Technology Fingerprinting.
Identifies web servers, frameworks, and CMS from HTTP headers, cookies, and DOM signatures.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage07TechnologyFingerprint(BaseStage):
    stage_id = "STAGE_07"
    name = "Technology Fingerprinting"

    async def execute(self, ctx: ScanContext) -> None:
        for url, data in ctx.live_hosts.items():
            ctx.check_cancelled()
            host = data.get("host", url)
            headers = data.get("headers", {})
            cookies = data.get("cookies", {})
            body = data.get("body_sample", "").lower()
            detected = set()

            # Server header
            server = headers.get("server", "")
            if server:
                detected.add(f"Server: {server}")

            # X-Powered-By
            x_powered = headers.get("x-powered-by", "")
            if x_powered:
                detected.add(f"Framework: {x_powered}")

            # Cookie heuristics
            if "phpsessid" in cookies:
                detected.add("Language: PHP")
            if "jsessionid" in cookies:
                detected.add("Language: Java")
            if "asp.net_sessionid" in cookies:
                detected.add("Framework: ASP.NET")

            # HTML signatures
            if "wp-content" in body or "wp-includes" in body:
                detected.add("CMS: WordPress")
            if "drupal" in body:
                detected.add("CMS: Drupal")
            if "__next" in body:
                detected.add("Framework: Next.js")
            if "react" in body:
                detected.add("Library: React")

            if detected:
                ctx.technologies[host] = list(detected)
                logger.info(f"Fingerprinted {host}: {', '.join(detected)}")
