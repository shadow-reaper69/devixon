"""
Security Boundary and Scope Enforcement Tests.
Verifies that out-of-scope targets, shell injection attempts, and unauthorized scans are strictly blocked.
"""

import pytest
from devixon.core.scope import ScopeProfile, normalize_target
from devixon.core.exceptions import ScopeViolationError, TargetValidationError


def test_out_of_scope_rejection():
    scope = ScopeProfile(
        primary_domain="auth.mycorp.internal",
        allowed_domains=["*.auth.mycorp.internal"],
        authorized_by_user=True,
    )

    in_scope, _ = scope.is_in_scope("public.mycorp.internal")
    assert in_scope is False

    in_scope, _ = scope.is_in_scope("mycorp.internal")
    assert in_scope is False


def test_path_traversal_and_command_injection_target_sanitization():
    # Attempt command injection strings in target
    with pytest.raises(TargetValidationError):
        normalize_target("example.com; rm -rf /")

    with pytest.raises(TargetValidationError):
        normalize_target("example.com | whoami")

    with pytest.raises(TargetValidationError):
        normalize_target("example.com && touch test")


def test_unauthorized_active_scan_enforcement():
    unauthorized_scope = ScopeProfile(
        primary_domain="demo.local",
        authorized_by_user=False,  # NOT authorized
    )
    with pytest.raises(ScopeViolationError):
        unauthorized_scope.validate_authorization()
