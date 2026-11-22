"""
Stage 00: Scope and Authorization Validation.
"""

from devixon.recon.base import BaseStage, ScanContext
from devixon.core.exceptions import ScopeViolationError, TargetValidationError
from devixon.core.scope import normalize_target
from devixon.core.logger import logger


class Stage00ScopeValidation(BaseStage):
    stage_id = "STAGE_00"
    name = "Scope & Authorization Validation"

    async def execute(self, ctx: ScanContext) -> None:
        # 1. Target normalization
        norm_target = normalize_target(ctx.target)
        ctx.target = norm_target

        # 2. Scope validation
        is_allowed, reason = ctx.scope_profile.is_in_scope(norm_target)
        if not is_allowed:
            raise ScopeViolationError(f"Target '{norm_target}' is NOT in authorized scope: {reason}")

        # 3. Authorization check if scan is active
        if ctx.scan_profile != "PASSIVE":
            ctx.scope_profile.validate_authorization()

        logger.info(f"Target '{norm_target}' scope and authorization verified: {reason}")
