"""
Base classes for DEVIXON Reconnaissance Pipeline Stages and Context.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field
from devixon.core.scope import ScopeProfile
from devixon.core.target import CanonicalTarget, parse_canonical_target
from devixon.core.exceptions import DevixonError, ScanCancelledError
from devixon.core.logger import logger
from devixon.database.repository import AssessmentRepository
from devixon.database.session import get_session
from devixon.database.models import ScanStage


class ScanContext:
    def __init__(
        self,
        assessment_id: str,
        target: str,
        scope_profile: ScopeProfile,
        scan_profile: str = "QUICK",
        target_model: Optional[CanonicalTarget] = None,
    ):
        self.assessment_id = assessment_id
        self.target = target
        self.scope_profile = scope_profile
        self.scan_profile = scan_profile
        self.is_cancelled = False

        if target_model is not None:
            self.target_model = target_model
        else:
            self.target_model = parse_canonical_target(target)

        self.scheme = self.target_model.scheme
        self.port = self.target_model.port
        self.base_path = self.target_model.base_path
        self.canonical_url = self.target_model.canonical_url
        self.service_identity = self.target_model.service_identity

        # Working data shared between stages
        self.discovered_subdomains: Set[str] = {self.target_model.hostname}
        self.subdomain_records: Dict[str, Dict[str, Any]] = {}  # sub -> {resolved_ip, status, source, records}
        self.dns_records: Dict[str, Dict[str, List[str]]] = {}  # host -> {record_type: [values]}
        self.live_hosts: Dict[str, Dict[str, Any]] = {}  # url -> info
        self.open_ports: Dict[str, List[int]] = {}  # host -> [ports]
        self.technologies: Dict[str, List[str]] = {}  # host -> [tech]
        self.discovered_urls: Set[str] = set()
        self.discovered_paths: List[Dict[str, Any]] = []
        self.internal_links: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.parameters: List[Dict[str, Any]] = []
        self.js_findings: List[Dict[str, Any]] = []
        self.js_assets: List[Dict[str, Any]] = []
        self.api_endpoints: List[str] = []
        self.posture_findings: List[Dict[str, Any]] = []
        self.stage_timings: Dict[str, float] = {}
        self.scan_errors: List[Dict[str, Any]] = []

    def check_cancelled(self):
        if self.is_cancelled:
            raise ScanCancelledError("Scan was interrupted/cancelled by user.")


class BaseStage:
    stage_id: str = "STAGE_XX"
    name: str = "Base Stage"

    async def execute(self, ctx: ScanContext) -> None:
        """Core stage logic to be implemented by subclasses."""
        raise NotImplementedError

    async def run(self, ctx: ScanContext) -> None:
        ctx.check_cancelled()
        logger.info(f"[{self.stage_id}] Starting: {self.name}")

        session = get_session()
        db_stage = ScanStage(
            assessment_id=ctx.assessment_id,
            stage_id=self.stage_id,
            name=self.name,
            status="RUNNING",
            start_time=datetime.now(timezone.utc),
            progress=0.0,
        )
        session.add(db_stage)
        session.commit()

        start_time = asyncio.get_event_loop().time()
        try:
            await self.execute(ctx)
            duration = asyncio.get_event_loop().time() - start_time
            ctx.stage_timings[self.stage_id] = duration

            db_stage.status = "COMPLETED"
            db_stage.progress = 1.0
            db_stage.end_time = datetime.now(timezone.utc)
            db_stage.duration = duration
            session.commit()
            logger.info(f"[{self.stage_id}] Completed: {self.name} ({duration:.2f}s)")

        except ScanCancelledError:
            db_stage.status = "CANCELLED"
            db_stage.end_time = datetime.now(timezone.utc)
            session.commit()
            raise

        except DevixonError as de:
            duration = asyncio.get_event_loop().time() - start_time
            db_stage.duration = duration
            db_stage.end_time = datetime.now(timezone.utc)
            err_dict = {
                "stage": self.stage_id,
                "name": self.name,
                "error": de.message,
                "recoverable": de.recoverable,
                "suggested_action": de.suggested_action,
            }
            ctx.scan_errors.append(err_dict)

            if de.recoverable:
                db_stage.status = "SKIPPED"
                db_stage.error_message = f"{de.message} (Action: {de.suggested_action or 'Continuing with native fallback'})"
                session.commit()
                logger.warning(f"[{self.stage_id}] Recoverable skip: {de.message}")
            else:
                db_stage.status = "FAILED"
                db_stage.error_message = de.message
                session.commit()
                logger.error(f"[{self.stage_id}] Stage failed: {de.message}")
                raise

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            db_stage.status = "FAILED"
            db_stage.duration = duration
            db_stage.end_time = datetime.now(timezone.utc)
            db_stage.error_message = str(e)
            session.commit()
            ctx.scan_errors.append({
                "stage": self.stage_id,
                "name": self.name,
                "error": str(e),
                "recoverable": False,
            })
            logger.error(f"[{self.stage_id}] Unexpected error: {str(e)}", exc_info=True)
            raise
        finally:
            session.close()
