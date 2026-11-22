"""
Stage 00: Scope and Authorization Validation.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.core.exceptions import ScopeViolationError
from devixon.core.logger import logger


class Stage00ScopeValidation(BaseStage):
    stage_id = "STAGE_00"
    name = "Scope & Authorization Validation"

    async def execute(self, ctx: ScanContext) -> None:
        target_to_check = ctx.target_model.canonical_url if ctx.target_model.target_type == "URL" else ctx.target_model.hostname

        # 1. Scope validation (validates host, port, base path, and path traversal)
        is_allowed, reason = ctx.scope_profile.is_in_scope(
            target_to_check,
            path=ctx.target_model.base_path,
            port=ctx.target_model.port,
        )
        if not is_allowed:
            raise ScopeViolationError(f"Target '{target_to_check}' is NOT in authorized scope: {reason}")

        # 2. Authorization check if scan is active
        if ctx.scan_profile != "PASSIVE":
            ctx.scope_profile.validate_authorization()

        ctx.discovered_subdomains.add(ctx.target_model.hostname)

        logger.info(f"Target '{target_to_check}' scope and authorization verified: {reason}")
