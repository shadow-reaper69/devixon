"""
Unit tests for DEVIXON Scope Engine.
"""

import pytest
from devixon.core.scope import ScopeProfile, normalize_target
from devixon.core.exceptions import ScopeViolationError, TargetValidationError


def test_target_normalization():
    assert normalize_target("https://sub.example.com:443/test?a=1") == "sub.example.com"
    assert normalize_target("HTTP://EXAMPLE.COM/") == "example.com"
    assert normalize_target("192.168.1.1:8080") == "192.168.1.1"

    with pytest.raises(TargetValidationError):
        normalize_target("")

    with pytest.raises(TargetValidationError):
        normalize_target("invalid target!#$@")


def test_scope_allowed_domains(sample_scope):
    in_scope, _ = sample_scope.is_in_scope("example.com")
    assert in_scope is True

    in_scope, _ = sample_scope.is_in_scope("api.example.com")
    assert in_scope is True

    in_scope, _ = sample_scope.is_in_scope("deep.sub.example.com")
    assert in_scope is True

    in_scope, _ = sample_scope.is_in_scope("partner.org")
    assert in_scope is True

    in_scope, _ = sample_scope.is_in_scope("attacker.com")
    assert in_scope is False

    in_scope, _ = sample_scope.is_in_scope("evilexample.com")
    assert in_scope is False


def test_scope_exclusions(sample_scope):
    # Explicit excluded host
    in_scope, reason = sample_scope.is_in_scope("admin.example.com")
    assert in_scope is False
    assert "excluded" in reason.lower()

    # Excluded path
    in_scope, reason = sample_scope.is_in_scope("api.example.com", path="/logout")
    assert in_scope is False
    assert "excluded" in reason.lower()


def test_scope_ips_and_cidr(sample_scope):
    in_scope, _ = sample_scope.is_in_scope("10.0.0.42")
    assert in_scope is True

    in_scope, _ = sample_scope.is_in_scope("10.0.0.5")  # Excluded
    assert in_scope is False

    in_scope, _ = sample_scope.is_in_scope("192.168.1.100")
    assert in_scope is True

    in_scope, _ = sample_scope.is_in_scope("192.168.1.101")
    assert in_scope is False


def test_scope_authorization_enforcement():
    unauthorized_scope = ScopeProfile(
        primary_domain="target.com",
        authorized_by_user=False,
    )
    with pytest.raises(ScopeViolationError):
        unauthorized_scope.validate_authorization()
