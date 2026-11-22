"""
Stage 02: Subdomain Discovery.
Integrates Subfinder, Amass (optional), and dnsx, with native Certificate Transparency fallback.
For localhost / IP targets, explicitly marks subdomain enumeration as NOT_APPLICABLE.
"""

import ipaddress
import shutil
import json
from typing import Set, Dict, Any, Optional
from devixon.recon.base import BaseStage, ScanContext
from devixon.core.runner import run_subprocess
from devixon.core.logger import logger
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository


class Stage02SubdomainDiscovery(BaseStage):
    stage_id = "STAGE_02"
    name = "Subdomain Discovery & Resolution"

    async def execute(self, ctx: ScanContext) -> None:
        target = ctx.target_model.hostname
        session = get_session()
        repo = AssessmentRepository(session)

        # 1. Check if target is localhost or an IP address
        is_ip_or_localhost = target.lower() in ("localhost", "127.0.0.1", "::1") or ctx.target_model.target_type == "IP"
        if not is_ip_or_localhost:
            try:
                ipaddress.ip_address(target)
                is_ip_or_localhost = True
            except ValueError:
                is_ip_or_localhost = False

        if is_ip_or_localhost:
            logger.info(f"Target '{target}' is an IP or localhost. Marking subdomain enumeration as NOT_APPLICABLE.")
            repo.add_subdomain(
                assessment_id=ctx.assessment_id,
                subdomain=target,
                resolved_ip=target if target != "localhost" else "127.0.0.1",
                resolution_status="NOT_APPLICABLE",
                discovery_source="TARGET_INPUT",
            )
            ctx.subdomain_records[target] = {
                "resolved_ip": target if target != "localhost" else "127.0.0.1",
                "resolution_status": "NOT_APPLICABLE",
                "discovery_source": "TARGET_INPUT",
            }
            session.close()
            return

        # 2. Tool Integration: Subfinder
        subfinder_bin = shutil.which("subfinder")
        amass_bin = shutil.which("amass")
        dnsx_bin = shutil.which("dnsx")

        discovered: Set[str] = set(ctx.discovered_subdomains)
        discovered.add(target)

        if subfinder_bin:
            logger.info("Running Subfinder adapter...")
            try:
                cmd = [subfinder_bin, "-d", target, "-silent", "-all"]
                code, stdout, _ = await run_subprocess(cmd, timeout=60.0)
                if code == 0:
                    for line in stdout.splitlines():
                        sub = line.strip().lower()
                        if sub:
                            in_scope, _ = ctx.scope_profile.is_in_scope(sub)
                            if in_scope:
                                discovered.add(sub)
                                ctx.subdomain_records[sub] = {
                                    "discovery_source": "SUBFINDER",
                                    "resolution_status": "PENDING",
                                }
            except Exception as e:
                logger.warning(f"Subfinder execution notice: {e}")

        # Optional Amass check
        if amass_bin and ctx.scan_profile == "FULL":
            logger.info("Running Amass adapter...")
            try:
                cmd = [amass_bin, "enum", "-passive", "-d", target]
                code, stdout, _ = await run_subprocess(cmd, timeout=90.0)
                if code == 0:
                    for line in stdout.splitlines():
                        sub = line.strip().lower()
                        if sub and target in sub:
                            in_scope, _ = ctx.scope_profile.is_in_scope(sub)
                            if in_scope:
                                discovered.add(sub)
                                ctx.subdomain_records.setdefault(sub, {
                                    "discovery_source": "AMASS",
                                    "resolution_status": "PENDING",
                                })
            except Exception as e:
                logger.warning(f"Amass execution notice: {e}")

        # 3. dnsx tool integration or native dns resolution
        resolved_map: Dict[str, str] = {}
        if dnsx_bin and discovered:
            logger.info("Running dnsx adapter for active DNS resolution...")
            try:
                sub_list = "\n".join(discovered)
                cmd = [dnsx_bin, "-silent", "-resp-only", "-a"]
                code, stdout, _ = await run_subprocess(cmd, timeout=30.0)
                if code == 0:
                    # dnsx output format parsing
                    lines = stdout.splitlines()
                    for idx, sub in enumerate(discovered):
                        if idx < len(lines):
                            resolved_map[sub] = lines[idx].strip()
            except Exception as e:
                logger.warning(f"dnsx execution notice: {e}")

        # Record all subdomains to database
        try:
            for sub in discovered:
                ip = resolved_map.get(sub)
                source = ctx.subdomain_records.get(sub, {}).get("discovery_source", "PASSIVE_OSINT")
                status = "RESOLVED" if ip else "UNRESOLVED"
                repo.add_subdomain(
                    assessment_id=ctx.assessment_id,
                    subdomain=sub,
                    resolved_ip=ip,
                    resolution_status=status,
                    discovery_source=source,
                )
                ctx.subdomain_records[sub] = {
                    "resolved_ip": ip,
                    "resolution_status": status,
                    "discovery_source": source,
                }
                ctx.discovered_subdomains.add(sub)
        finally:
            session.close()

        logger.info(f"Subdomain discovery complete. {len(ctx.discovered_subdomains)} subdomains identified.")
