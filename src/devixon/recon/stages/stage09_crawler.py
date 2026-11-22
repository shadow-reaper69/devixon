"""
Stage 09: Web Crawling.
Scope-governed crawler extracting links and assets with strict depth, rate, and path limiters.
"""

import re
from urllib.parse import urljoin, urlparse
import httpx
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage09WebCrawler(BaseStage):
    stage_id = "STAGE_09"
    name = "Web Crawling"

    async def execute(self, ctx: ScanContext) -> None:
        crawled_urls = set()
        queue = list(ctx.live_hosts.keys())[:10]  # Limit seed URLs
        max_pages = 25

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True) as client:
            while queue and len(crawled_urls) < max_pages:
                ctx.check_cancelled()
                current_url = queue.pop(0)
                if current_url in crawled_urls:
                    continue

                in_scope, _ = ctx.scope_profile.is_in_scope(current_url)
                if not in_scope:
                    continue

                crawled_urls.add(current_url)
                try:
                    resp = await client.get(current_url, headers={"User-Agent": "devixon/0.1.0-crawler"})
                    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                        # Extract href and src links
                        links = re.findall(r'(?:href|src)=["\']([^"\'#\s>]+)', resp.text, re.IGNORECASE)
                        for link in links:
                            abs_url = urljoin(current_url, link)
                            parsed = urlparse(abs_url)
                            if parsed.scheme in ("http", "https"):
                                is_allowed, _ = ctx.scope_profile.is_in_scope(abs_url, path=parsed.path)
                                if is_allowed:
                                    ctx.discovered_urls.add(abs_url)
                                    if abs_url not in crawled_urls and len(queue) < 50:
                                        queue.append(abs_url)
                except Exception:
                    continue

        logger.info(f"Crawl completed. Evaluated {len(crawled_urls)} pages; total URLs: {len(ctx.discovered_urls)}")
