"""
Pipeline Orchestrator for DEVIXON Reconnaissance Framework.
Coordinates stages, handles cancellation, logs metrics, and manages presets.
"""

import asyncio
from typing import List, Optional, Type
from devixon.recon.base import BaseStage, ScanContext
from devixon.recon.stages.stage00_scope import Stage00ScopeValidation
from devixon.recon.stages.stage01_osint import Stage01PassiveOSINT
from devixon.recon.stages.stage02_subdomains import Stage02SubdomainDiscovery
from devixon.recon.stages.stage03_dns import Stage03DNSIntelligence
from devixon.recon.stages.stage04_correlation import Stage04AssetCorrelation
from devixon.recon.stages.stage05_live_hosts import Stage05LiveHosts
from devixon.recon.stages.stage06_services import Stage06ServiceDiscovery
from devixon.recon.stages.stage07_fingerprint import Stage07TechnologyFingerprint
from devixon.recon.stages.stage08_urls import Stage08URLIntelligence
from devixon.recon.stages.stage09_crawler import Stage09WebCrawler
from devixon.recon.stages.stage10_endpoints import Stage10EndpointExtraction
from devixon.recon.stages.stage11_javascript import Stage11JavaScriptIntelligence
from devixon.recon.stages.stage12_apis import Stage12APISurvey
from devixon.recon.stages.stage13_content import Stage13ContentDiscovery
from devixon.recon.stages.stage14_posture import Stage14SecurityPosture
from devixon.recon.stages.stage15_normalization import Stage15EvidenceNormalization
from devixon.recon.stages.stage16_ai import Stage16AIAnalysis
from devixon.recon.stages.stage17_reporting import Stage17ReportGeneration

from devixon.database.session import get_session
from devixon.database.repository import AssessmentRepository
from devixon.core.logger import logger
from devixon.core.exceptions import ScanCancelledError

STAGE_REGISTRY: List[Type[BaseStage]] = [
    Stage00ScopeValidation,
    Stage01PassiveOSINT,
    Stage02SubdomainDiscovery,
    Stage03DNSIntelligence,
    Stage04AssetCorrelation,
    Stage05LiveHosts,
    Stage06ServiceDiscovery,
    Stage07TechnologyFingerprint,
    Stage08URLIntelligence,
    Stage09WebCrawler,
    Stage10EndpointExtraction,
    Stage11JavaScriptIntelligence,
    Stage12APISurvey,
    Stage13ContentDiscovery,
    Stage14SecurityPosture,
    Stage15EvidenceNormalization,
    Stage16AIAnalysis,
    Stage17ReportGeneration,
]


class ReconPipeline:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.stages: List[BaseStage] = self._resolve_stages(ctx.scan_profile)

    def _resolve_stages(self, profile: str) -> List[BaseStage]:
        profile = profile.upper()
        if profile == "SUBDOMAINS":
            allowed_ids = {"STAGE_00", "STAGE_01", "STAGE_02", "STAGE_03", "STAGE_04", "STAGE_17"}
        elif profile == "HOSTS":
            allowed_ids = {"STAGE_00", "STAGE_05", "STAGE_06", "STAGE_07", "STAGE_17"}
        elif profile == "CRAWL":
            allowed_ids = {"STAGE_00", "STAGE_05", "STAGE_09", "STAGE_17"}
        elif profile == "PATHS":
            allowed_ids = {"STAGE_00", "STAGE_05", "STAGE_13", "STAGE_17"}
        elif profile == "URLS":
            allowed_ids = {"STAGE_00", "STAGE_08", "STAGE_10", "STAGE_17"}
        elif profile == "ENDPOINTS":
            allowed_ids = {"STAGE_00", "STAGE_05", "STAGE_08", "STAGE_09", "STAGE_10", "STAGE_11", "STAGE_12", "STAGE_17"}
        elif profile == "PASSIVE":
            allowed_ids = {
                "STAGE_00", "STAGE_01", "STAGE_02", "STAGE_03", "STAGE_04",
                "STAGE_08", "STAGE_15", "STAGE_16", "STAGE_17"
            }
        elif profile == "QUICK":
            allowed_ids = {
                "STAGE_00", "STAGE_01", "STAGE_02", "STAGE_03", "STAGE_04",
                "STAGE_05", "STAGE_06", "STAGE_07", "STAGE_10", "STAGE_14",
                "STAGE_15", "STAGE_16", "STAGE_17"
            }
        else:  # FULL
            allowed_ids = {cls.stage_id for cls in STAGE_REGISTRY}

        return [cls() for cls in STAGE_REGISTRY if cls.stage_id in allowed_ids]

    async def execute_all(self) -> None:
        session = get_session()
        repo = AssessmentRepository(session)

        repo.update_status(self.ctx.assessment_id, "RUNNING")
        logger.info(f"Starting DEVIXON Reconnaissance Pipeline [Profile: {self.ctx.scan_profile}] for target {self.ctx.target}")

        try:
            for stage in self.stages:
                self.ctx.check_cancelled()
                await stage.run(self.ctx)

            repo.update_status(
                self.ctx.assessment_id,
                "COMPLETED",
                summary={"timings": self.ctx.stage_timings}
            )
            logger.info("Pipeline completed successfully.")

        except ScanCancelledError:
            repo.update_status(self.ctx.assessment_id, "CANCELLED")
            logger.warning("Pipeline execution cancelled.")
            raise
        except Exception as e:
            repo.update_status(self.ctx.assessment_id, "FAILED")
            logger.error(f"Pipeline failed: {e}")
            raise
        finally:
            session.close()
