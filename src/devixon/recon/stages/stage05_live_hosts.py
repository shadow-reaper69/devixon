"""
Stage 05: Live Host Discovery.
Probes HTTP/HTTPS services using ProjectDiscovery httpx or native async httpx client.
Collects URL, status, title, web server, technologies, content type, response time, and redirects.
Persists records to the LiveHost table with scheme, hostname, and port.
"""

import time
import shutil
import re
from typing import Dict, Any, List
from urllib.parse import urlsplit
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

        # Native Async Prober (Highly optimized, robust, and safe)
        timeout = httpx.Timeout(5.0, connect=3.0)
        limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)

        # 1. Determine candidate hosts
        hosts_to_probe = set(ctx.discovered_subdomains)
        if ctx.target_model.hostname:
            hosts_to_probe.add(ctx.target_model.hostname)

        # 2. Build list of URLs to probe based on target model, open ports, and scope allowed ports
        urls_to_probe: List[str] = []
        if ctx.target_model.target_type == "URL":
            urls_to_probe.append(ctx.target_model.canonical_url)

        for host in hosts_to_probe:
            # Ports to check on this host
            ports: List[int] = []
            if ctx.target_model.port and host == ctx.target_model.hostname:
                ports.append(ctx.target_model.port)
            if ctx.scope_profile.allowed_ports:
                for p in ctx.scope_profile.allowed_ports:
                    if p not in ports:
                        ports.append(p)
            if host in ctx.open_ports:
                for p in ctx.open_ports[host]:
                    if p not in ports:
                        ports.append(p)
            if not ports:
                # Default ports only if no ports specified anywhere
                ports = [80, 443]

            for port in ports:
                # Check port authorization before probing
                is_port_allowed, _ = ctx.scope_profile.is_in_scope(host, port=port)
                if not is_port_allowed:
                    continue

                schemes = ["http", "https"] if port not in (443, 8443) else ["https", "http"]
                if ctx.target_model.scheme and host == ctx.target_model.hostname and port == ctx.target_model.port:
                    schemes = [ctx.target_model.scheme]

                base_path = ctx.target_model.base_path if (host == ctx.target_model.hostname and (port == ctx.target_model.port or ctx.target_model.target_type == "URL")) else "/"

                for proto in schemes:
                    if (proto == "http" and port != 80) or (proto == "https" and port != 443):
                        u = f"{proto}://{host}:{port}{base_path}"
                    else:
                        u = f"{proto}://{host}{base_path}"
                    if u not in urls_to_probe:
                        urls_to_probe.append(u)

        # 3. Probe URLs and record confirmed web services
        try:
            async with httpx.AsyncClient(timeout=timeout, limits=limits, verify=False, follow_redirects=True) as client:
                for url in urls_to_probe:
                    ctx.check_cancelled()
                    p_url = urlsplit(url)
                    host = p_url.hostname or ctx.target_model.hostname
                    port = p_url.port or (443 if p_url.scheme == "https" else 80)

                    # Validate scope
                    is_in, reason = ctx.scope_profile.is_in_scope(url, path=p_url.path, port=port)
                    if not is_in:
                        logger.debug(f"Skipping out-of-scope probe URL '{url}': {reason}")
                        continue

                    start_t = time.perf_counter()
                    try:
                        resp = await client.get(url, headers={"User-Agent": "devixon/0.2.0-probe"})
                        elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)

                        server = resp.headers.get("server", "")
                        content_type = resp.headers.get("content-type", "")
                        title = self._extract_title(resp.text)
                        redirect_dest = str(resp.url) if str(resp.url).rstrip("/") != url.rstrip("/") else None

                        # If redirect occurred, validate authorization on destination
                        if redirect_dest:
                            is_dest_in_scope, dest_reason = ctx.scope_profile.is_in_scope(redirect_dest)
                            if not is_dest_in_scope:
                                logger.warning(f"Redirect destination '{redirect_dest}' is OUT OF SCOPE ({dest_reason}). Preserving original url only.")

                        techs = self._detect_technologies(resp)
                        service_identity = f"{p_url.scheme}://{host}:{port}"

                        lh = repo.add_live_host(
                            assessment_id=ctx.assessment_id,
                            url=url,
                            host=service_identity,
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
                            "host": service_identity,
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
                    except (httpx.ConnectError, httpx.ConnectTimeout) as ce:
                        logger.debug(f"Connection failed or timed out for {url}: {ce}")
                    except httpx.HTTPError as he:
                        logger.debug(f"HTTP probe error on {url}: {he}")
                    except Exception as e:
                        logger.debug(f"Unexpected probe error for {url}: {e}")

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
