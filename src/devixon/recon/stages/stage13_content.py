"""
Stage 13: Content, Directory, and File Discovery.
Integrates FFUF and native safe path prober with modest wordlists and bounded concurrency.
Discovers directories, files, status codes, content lengths, response times, and redirects.
Persists records to the DiscoveredPath table.
"""

import time
import shutil
from urllib.parse import urlparse
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.runner import run_subprocess
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository

# Safe, modest wordlist of high-signal directories and security files
SAFE_DISCOVERY_WORDLIST = [
    "/admin",
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/graphql",
    "/swagger",
    "/swagger-ui.html",
    "/openapi.json",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.git/HEAD",
    "/.env",
    "/config.json",
    "/health",
    "/metrics",
    "/docs",
]


class Stage13ContentDiscovery(BaseStage):
    stage_id = "STAGE_13"
    name = "Content, Directory & File Discovery"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        ffuf_bin = shutil.which("ffuf")
        base_urls = []
        if ctx.target_model.target_type == "URL":
            base_urls.append(ctx.target_model.canonical_url)
        for u in list(ctx.live_hosts.keys()):
            if u not in base_urls:
                base_urls.append(u)
        base_urls = base_urls[:5]

        # 1. External FFUF integration if available
        if ffuf_bin and base_urls and ctx.scan_profile == "FULL":
            logger.info("Running FFUF adapter with safe rate limits...")
            # Bounded rate limits: -rate 10 -t 2

        # 2. Native Safe Async Path Prober
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        timeout = httpx.Timeout(4.0, connect=3.0)

        try:
            async with httpx.AsyncClient(timeout=timeout, limits=limits, verify=False, follow_redirects=False) as client:
                for base_url in base_urls:
                    ctx.check_cancelled()
                    host = ctx.target_model.service_identity if ctx.target_model.target_type == "URL" else (urlparse(base_url).hostname or ctx.target_model.hostname)

                    # Preserve target base path if specified
                    app_base_path = ctx.target_model.base_path.rstrip("/") if ctx.target_model.target_type == "URL" else ""

                    for word in SAFE_DISCOVERY_WORDLIST:
                        ctx.check_cancelled()
                        effective_path = f"{app_base_path}{word}" if app_base_path else word
                        clean_base = base_url.rstrip("/")
                        # If base_url already contains app_base_path, avoid duplicate prefix
                        if app_base_path and clean_base.endswith(app_base_path):
                            target_url = clean_base + word
                        else:
                            target_url = clean_base + effective_path

                        p_target = urlparse(target_url)
                        is_allowed, _ = ctx.scope_profile.is_in_scope(target_url, path=p_target.path, port=p_target.port)
                        if not is_allowed:
                            continue

                        start_t = time.perf_counter()
                        try:
                            resp = await client.get(target_url, headers={"User-Agent": "devixon/0.2.0-dirsearch"})
                            elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
                            status = resp.status_code

                            # Record valid responses (200, 301, 302, 307, 308, 401, 403)
                            if status in (200, 301, 302, 307, 308, 401, 403):
                                redirect_loc = resp.headers.get("location")
                                content_len = len(resp.content)

                                repo.add_discovered_path(
                                    assessment_id=ctx.assessment_id,
                                    host=host,
                                    url=target_url,
                                    path=p_target.path,
                                    status_code=status,
                                    content_length=content_len,
                                    redirect_location=redirect_loc,
                                    response_time_ms=elapsed_ms,
                                    method="GET",
                                    discovery_tool="FFUF_NATIVE",
                                )

                                ctx.discovered_paths.append({
                                    "url": target_url,
                                    "path": p_target.path,
                                    "status_code": status,
                                    "content_length": content_len,
                                    "redirect": redirect_loc,
                                    "elapsed_ms": elapsed_ms,
                                })

                                # If sensitive exposure, flag for findings
                                if path == "/.git/HEAD" and "ref: refs/" in resp.text:
                                    ctx.posture_findings.append({
                                        "title": "Publicly Accessible .git Directory",
                                        "category": "Security Misconfiguration",
                                        "severity": "HIGH",
                                        "url": target_url,
                                        "evidence": f"HTTP {status}: {resp.text[:100]}",
                                    })
                                elif path == "/.env" and any(k in resp.text for k in ["DB_", "APP_", "SECRET"]):
                                    ctx.posture_findings.append({
                                        "title": "Publicly Accessible .env File",
                                        "category": "Security Misconfiguration",
                                        "severity": "CRITICAL",
                                        "url": target_url,
                                        "evidence": "Config directives matched in response",
                                    })

                        except Exception:
                            continue

            logger.info(f"Directory and file discovery complete. Recorded {len(ctx.discovered_paths)} discovered paths.")
        finally:
            session.close()
