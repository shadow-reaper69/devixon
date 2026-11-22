"""
Stage 09: Internal Link Crawling.
Integrates Katana CLI and native async HTML/JS crawler.
Extracts internal and external links, methods, link types, crawl depth, and status codes.
Persists records to the InternalLink table.
"""

import re
import shutil
from urllib.parse import urljoin, urlparse
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.runner import run_subprocess
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository


class Stage09WebCrawler(BaseStage):
    stage_id = "STAGE_09"
    name = "Internal Link Crawling"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        katana_bin = shutil.which("katana")
        crawled_urls = set()
        queue = [(u, 1) for u in list(ctx.live_hosts.keys())[:10]]
        max_pages = 30
        max_depth = 3

        # 1. External Katana integration if available
        if katana_bin and ctx.live_hosts:
            logger.info("Running Katana crawler adapter...")
            try:
                seed_url = list(ctx.live_hosts.keys())[0]
                cmd = [
                    katana_bin,
                    "-u", seed_url,
                    "-silent",
                    "-depth", "2",
                    "-concurrency", "3",
                    "-crawl-duration", "20s",
                ]
                code, stdout, _ = await run_subprocess(cmd, timeout=30.0)
                if code == 0:
                    for line in stdout.splitlines():
                        dest_url = line.strip()
                        if dest_url:
                            is_in_scope, _ = ctx.scope_profile.is_in_scope(dest_url)
                            repo.add_internal_link(
                                assessment_id=ctx.assessment_id,
                                source_url=seed_url,
                                destination_url=dest_url,
                                method="GET",
                                link_type="katana_crawl",
                                is_internal=is_in_scope,
                                crawl_depth=1,
                            )
                            if is_in_scope:
                                ctx.discovered_urls.add(dest_url)
            except Exception as e:
                logger.warning(f"Katana crawler notice: {e}")

        # 2. Native Robust Async Crawler
        async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
            while queue and len(crawled_urls) < max_pages:
                ctx.check_cancelled()
                current_url, depth = queue.pop(0)
                if current_url in crawled_urls:
                    continue

                in_scope, _ = ctx.scope_profile.is_in_scope(current_url)
                if not in_scope:
                    continue

                crawled_urls.add(current_url)
                try:
                    resp = await client.get(current_url, headers={"User-Agent": "devixon/0.2.0-crawler"})
                    content_type = resp.headers.get("content-type", "").lower()

                    if "text/html" in content_type:
                        # A tags (a_href)
                        href_matches = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\'>\s#]+)["\']', resp.text, re.IGNORECASE)
                        for href in href_matches:
                            dest = urljoin(current_url, href)
                            p = urlparse(dest)
                            if p.scheme in ("http", "https"):
                                is_in, _ = ctx.scope_profile.is_in_scope(dest, path=p.path)
                                repo.add_internal_link(
                                    assessment_id=ctx.assessment_id,
                                    source_url=current_url,
                                    destination_url=dest,
                                    method="GET",
                                    link_type="a_href",
                                    is_internal=is_in,
                                    status_code=None,
                                    crawl_depth=depth,
                                )
                                ctx.internal_links.append({
                                    "source": current_url,
                                    "destination": dest,
                                    "type": "a_href",
                                    "is_internal": is_in,
                                    "depth": depth,
                                })
                                if is_in:
                                    ctx.discovered_urls.add(dest)
                                    if depth < max_depth and dest not in crawled_urls and len(queue) < 60:
                                        queue.append((dest, depth + 1))

                        # Form actions (form_action)
                        form_matches = re.findall(r'<form\s+(?:[^>]*?\s+)?action=["\']([^"\'>\s]*)["\'](?:\s+[^>]*?method=["\']([^"\'>\s]+)["\'])?', resp.text, re.IGNORECASE)
                        for action, method in form_matches:
                            action_url = urljoin(current_url, action) if action else current_url
                            form_method = method.upper() if method else "GET"
                            is_in, _ = ctx.scope_profile.is_in_scope(action_url)
                            repo.add_internal_link(
                                assessment_id=ctx.assessment_id,
                                source_url=current_url,
                                destination_url=action_url,
                                method=form_method,
                                link_type="form_action",
                                is_internal=is_in,
                                crawl_depth=depth,
                            )
                            if is_in:
                                ctx.discovered_urls.add(action_url)

                        # Script sources (script_src)
                        script_matches = re.findall(r'<script\s+(?:[^>]*?\s+)?src=["\']([^"\'>\s]+)["\']', resp.text, re.IGNORECASE)
                        for src in script_matches:
                            script_url = urljoin(current_url, src)
                            is_in, _ = ctx.scope_profile.is_in_scope(script_url)
                            repo.add_internal_link(
                                assessment_id=ctx.assessment_id,
                                source_url=current_url,
                                destination_url=script_url,
                                method="GET",
                                link_type="script_src",
                                is_internal=is_in,
                                crawl_depth=depth,
                            )
                            if is_in:
                                ctx.discovered_urls.add(script_url)

                except Exception:
                    continue

        session.close()
        logger.info(f"Crawling complete. Evaluated {len(crawled_urls)} pages; found {len(ctx.internal_links)} links.")
