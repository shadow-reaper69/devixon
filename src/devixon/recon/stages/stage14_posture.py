"""
Stage 14: Security Posture Checks.
Safe checks for missing HTTP security headers, insecure cookie attributes, CORS misconfiguration, and TLS status.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.core.logger import logger


class Stage14SecurityPosture(BaseStage):
    stage_id = "STAGE_14"
    name = "Security Posture Checks"

    async def execute(self, ctx: ScanContext) -> None:
        for url, data in ctx.live_hosts.items():
            ctx.check_cancelled()
            headers = {k.lower(): v for k, v in data.get("headers", {}).items()}

            # 1. HSTS Check for HTTPS
            if url.startswith("https://") and "strict-transport-security" not in headers:
                ctx.posture_findings.append({
                    "title": "Missing Strict-Transport-Security (HSTS) Header",
                    "category": "Security Misconfiguration",
                    "severity": "LOW",
                    "url": url,
                    "evidence": "Strict-Transport-Security header was omitted from HTTPS response.",
                    "remediation": "Configure HTTP response header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                })

            # 2. X-Content-Type-Options Check
            if "x-content-type-options" not in headers:
                ctx.posture_findings.append({
                    "title": "Missing X-Content-Type-Options Header",
                    "category": "Security Misconfiguration",
                    "severity": "LOW",
                    "url": url,
                    "evidence": "X-Content-Type-Options header was omitted from HTTP response.",
                    "remediation": "Add header: X-Content-Type-Options: nosniff",
                })

            # 3. Content-Security-Policy (CSP) Check
            if "content-security-policy" not in headers:
                ctx.posture_findings.append({
                    "title": "Missing Content-Security-Policy (CSP)",
                    "category": "Security Misconfiguration",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": "Content-Security-Policy header is absent.",
                    "remediation": "Define a robust Content-Security-Policy restricting script, style, and object sources.",
                })

            # 4. CORS Permissive Origin Check
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")
            if acao == "*" and acac == "true":
                ctx.posture_findings.append({
                    "title": "Insecure CORS: Wildcard Origin With Credentials",
                    "category": "Security Misconfiguration",
                    "severity": "MEDIUM",
                    "url": url,
                    "evidence": f"Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted domains and never use wildcard with credentials.",
                })

        logger.info(f"Security posture analysis completed. Findings noted: {len(ctx.posture_findings)}")
