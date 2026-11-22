"""
Stage 15: Evidence Normalization and Finding Persistence.
Deduplicates findings, generates hashes, and persists structured Finding and Evidence records.
"""

import hashlib
from devixon.recon.base import BaseStage, ScanContext
from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository
from devixon.database.models import Asset
from devixon.security.cvss import calculate_cvss_base
from devixon.core.logger import logger


class Stage15EvidenceNormalization(BaseStage):
    stage_id = "STAGE_15"
    name = "Evidence Normalization"

    async def execute(self, ctx: ScanContext) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        try:
            seen_titles = set()

            for item in ctx.posture_findings:
                title = item.get("title", "")
                if title in seen_titles:
                    continue
                seen_titles.add(title)

                sev = item.get("severity", "LOW")
                # Calculate standard CVSS based on severity
                if sev == "CRITICAL":
                    score, _, vector = calculate_cvss_base(c="H", i="H", a="H")
                elif sev == "HIGH":
                    score, _, vector = calculate_cvss_base(c="H", i="L", a="N")
                elif sev == "MEDIUM":
                    score, _, vector = calculate_cvss_base(c="L", i="L", a="N")
                else:
                    score, _, vector = calculate_cvss_base(c="N", i="L", a="N")

                finding = repo.add_finding(
                    assessment_id=ctx.assessment_id,
                    title=title,
                    category=item.get("category", "Security Misconfiguration"),
                    severity=sev,
                    cvss_score=score,
                    cvss_vector=vector,
                    confidence="CONFIRMED" if "Header" in title else "LIKELY",
                    verification_status="CONFIRMED" if "Header" in title else "NEEDS_REVIEW",
                    description=f"Automated posture check identified {title} on target.",
                    impact="Reduces defense-in-depth posture or permits client-side browser attacks.",
                    reproduction_steps=f"Inspect HTTP response headers for target URL: {item.get('url', ctx.target)}",
                    remediation=item.get("remediation", "Apply defensive configuration guidelines."),
                )

                ev_data = item.get("evidence", "")
                ev_hash = hashlib.sha256(ev_data.encode("utf-8")).hexdigest()

                repo.add_evidence(
                    finding_id=finding.id,
                    evidence_type="HTTP_HEADER" if "Header" in title else "HTTP_RESPONSE",
                    description="Observed HTTP response data",
                    sanitized_data=ev_data,
                    source="DEVIXON_SCANNER",
                    data_hash=ev_hash,
                )

        finally:
            session.close()

        logger.info(f"Evidence normalized and findings persisted.")
