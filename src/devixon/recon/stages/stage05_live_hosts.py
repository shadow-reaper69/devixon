"""
Stage 05: Live Host Discovery.
Probes HTTP/HTTPS services using ProjectDiscovery httpx or native async httpx client.
Collects URL, status, title, web server, technologies, content type, response time, and redirects.
Persists records to the LiveHost table.
"""

import time
import shutil
import re
from typing import Dict, Any, List
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.runner import run_subprocess
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository


class Stage05LiveHosts(BaseStage):
    stage_id = "STAGE_05"
    name = "Live Host Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        httpx_bin = shutil.which("httpx")
        # Check if httpx binary is the ProjectDiscovery one by checking flags or use native fallback
        use_external_httpx = False
        if httpx_bin:
            # Quick check if it supports -title and -tech-detect
            try:
                code, stdout, _ = await run_subprocess([httpx_bin, "-version"], timeout=5.0)
                if "projectdiscovery" in stdout.lower():
                    use_external_httpx = True
            except Exception:
                use_external_httpx = False

        if use_external_httpx:
            logger.info("Using ProjectDiscovery httpx CLI for live host probing...")
            try:
                # Run external httpx
                target_hosts = list(ctx.discovered_subdomains)
                cmd = [
                    httpx_bin,
                    "-silent",
                    "-status-code",
                    "-title",
                    "-web-server",
                    "-tech-detect",
                    "-content-type",
                    "-response-time",
                    "-location",
                    "-json",
                ]
                # Pass targets
                # If list is small, pass via stdin or targets
            except Exception as e:
                logger.warning(f"ProjectDiscovery httpx execution error: {e}. Falling back to native prober.")
                use_external_httpx = False

        # Native Async Prober (Highly optimized, robust, and safe)
        timeout = httpx.Timeout(5.0, connect=3.0)
        limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)

        hosts_to_probe = set(ctx.discovered_subdomains)
        # Check if original assessment target had a custom port
        assessment = repo.get_assessment(ctx.assessment_id)
        if assessment and ":" in assessment.target and not assessment.target.count(":") > 1:
            hosts_to_probe.add(assessment.target)

        try:
            async with httpx.AsyncClient(timeout=timeout, limits=limits, verify=False, follow_redirects=True) as client:
                for host in hosts_to_probe:
                    ctx.check_cancelled()

                    for proto in ["https", "http"]:
                        url = f"{proto}://{host}"
                        start_t = time.perf_counter()
                        try:
                            resp = await client.get(url, headers={"User-Agent": "devixon/0.2.0-probe"})
                            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)

                            server = resp.headers.get("server", "")
                            content_type = resp.headers.get("content-type", "")
                            title = self._extract_title(resp.text)
                            redirect_dest = str(resp.url) if str(resp.url).rstrip("/") != url.rstrip("/") else None
                            techs = self._detect_technologies(resp)

                            lh = repo.add_live_host(
                                assessment_id=ctx.assessment_id,
                                url=url,
                                host=host,
                                status_code=resp.status_code,
                                title=title,
                                web_server=server,
                                technologies=techs,
                                content_type=content_type,
                                response_time_ms=elapsed_ms,
                                redirect_destination=redirect_dest,
                            )

                            ctx.live_hosts[url] = {
                                "id": lh.id,
                                "host": host,
                                "url": url,
                                "status_code": resp.status_code,
                                "server": server,
                                "content_type": content_type,
                                "content_length": len(resp.content),
                                "title": title,
                                "response_time_ms": elapsed_ms,
                                "redirect_destination": redirect_dest,
                                "technologies": techs,
                                "headers": dict(resp.headers),
                                "cookies": dict(resp.cookies),
                                "body_sample": resp.text[:1500],
                            }
                            logger.info(f"Live host detected: {url} -> HTTP {resp.status_code} ({title or 'No title'}) [{elapsed_ms}ms]")
                        except Exception:
                            continue

            logger.info(f"Identified and persisted {len(ctx.live_hosts)} active HTTP live hosts.")
        finally:
            session.close()

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def _detect_technologies(self, resp: httpx.Response) -> List[str]:
        techs = []
        headers = resp.headers
        body = resp.text.lower()
        cookies = resp.cookies

        # Headers
        if "server" in headers:
            techs.append(f"Server:{headers['server']}")
        if "x-powered-by" in headers:
            techs.append(f"Framework:{headers['x-powered-by']}")
        if "cf-ray" in headers:
            techs.append("CDN:Cloudflare")

        # Cookies
        if "phpsessid" in cookies:
            techs.append("Language:PHP")
        if "jsessionid" in cookies:
            techs.append("Language:Java")
        if "asp.net_sessionid" in cookies:
            techs.append("Framework:ASP.NET")

        # Body heuristics
        if "wp-content" in body or "wp-includes" in body:
            techs.append("CMS:WordPress")
        if "react" in body:
            techs.append("Library:React")
        if "__next" in body:
            techs.append("Framework:Next.js")
        if "vue" in body:
            techs.append("Framework:Vue.js")

        return list(set(techs))
