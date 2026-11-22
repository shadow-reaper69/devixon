"""
Unit tests for DEVIXON Canonical Target Model & URL Parser.
Tests domain-only, IPv4, custom ports, base paths, query strings, traversal, normalization, and scope enforcement.
"""

import pytest
from devixon.core.target import CanonicalTarget, parse_canonical_target
from devixon.core.scope import ScopeProfile, normalize_target
from devixon.core.exceptions import TargetValidationError, ScopeViolationError


def test_target_domain_only():
    ct = parse_canonical_target("example.com")
    assert ct.hostname == "example.com"
    assert ct.target_type == "DOMAIN"
    assert ct.base_path == "/"
    assert ct.port is None
    assert ct.scheme is None
    assert ct.effective_scheme == "https"
    assert ct.effective_port == 443
    assert ct.canonical_url == "https://example.com/"
    assert ct.service_identity == "https://example.com:443"


def test_target_ipv4_only():
    ct = parse_canonical_target("127.0.0.1")
    assert ct.hostname == "127.0.0.1"
    assert ct.target_type == "IP"
    assert ct.base_path == "/"
    assert ct.effective_scheme == "http"
    assert ct.effective_port == 80
    assert ct.canonical_url == "http://127.0.0.1/"
    assert ct.service_identity == "http://127.0.0.1:80"


def test_target_http_custom_port():
    ct = parse_canonical_target("http://127.0.0.1:8080/DVWA/")
    assert ct.hostname == "127.0.0.1"
    assert ct.port == 8080
    assert ct.scheme == "http"
    assert ct.base_path == "/DVWA/"
    assert ct.target_type == "URL"
    assert ct.canonical_url == "http://127.0.0.1:8080/DVWA/"
    assert ct.service_identity == "http://127.0.0.1:8080"


def test_target_https_url():
    ct = parse_canonical_target("https://example.com/app/")
    assert ct.hostname == "example.com"
    assert ct.port == 443
    assert ct.scheme == "https"
    assert ct.base_path == "/app/"
    assert ct.target_type == "URL"
    assert ct.canonical_url == "https://example.com/app/"
    assert ct.service_identity == "https://example.com:443"


def test_target_url_with_base_path():
    ct = parse_canonical_target("http://127.0.0.1:8080/DVWA")
    assert ct.hostname == "127.0.0.1"
    assert ct.port == 8080
    assert ct.base_path == "/DVWA"
    assert ct.canonical_url == "http://127.0.0.1:8080/DVWA"


def test_target_with_query_strings():
    ct = parse_canonical_target("http://127.0.0.1:8080/DVWA/?id=1&debug=true")
    assert ct.hostname == "127.0.0.1"
    assert ct.port == 8080
    assert ct.base_path == "/DVWA/"
    assert ct.query == "id=1&debug=true"
    assert ct.canonical_url == "http://127.0.0.1:8080/DVWA/"


def test_target_invalid_urls():
    with pytest.raises(TargetValidationError):
        parse_canonical_target("")

    with pytest.raises(TargetValidationError):
        parse_canonical_target("   ")

    with pytest.raises(TargetValidationError):
        parse_canonical_target("ftp://example.com/files")

    with pytest.raises(TargetValidationError):
        parse_canonical_target("http://example.com:999999/")


def test_target_base_path_traversal_attempts():
    with pytest.raises(TargetValidationError):
        parse_canonical_target("http://127.0.0.1:8080/DVWA/../secret")

    with pytest.raises(TargetValidationError):
        parse_canonical_target("http://127.0.0.1:8080/../etc/passwd")


def test_target_normalization_and_preservation():
    # Explicit port 80 must not be silently stripped
    ct1 = parse_canonical_target("http://127.0.0.1:80/")
    assert ct1.port == 80
    assert "80" in ct1.canonical_url

    # Multiple redundant slashes normalized cleanly
    ct2 = parse_canonical_target("http://127.0.0.1:8080//DVWA//index.php")
    assert ct2.base_path == "/DVWA/index.php"


def test_scope_out_of_scope_port():
    scope = ScopeProfile(
        primary_domain="http://127.0.0.1:8080/DVWA/",
        allowed_ips=["127.0.0.1"],
        allowed_ports=[8080],
        allowed_paths=["/DVWA/"],
        authorized_by_user=True,
    )

    # In-scope port 8080
    allowed, _ = scope.is_in_scope("http://127.0.0.1:8080/DVWA/index.php")
    assert allowed is True

    # Out-of-scope port 80 (e.g. CTFd)
    allowed, reason = scope.is_in_scope("http://127.0.0.1:80/challenges")
    assert allowed is False
    assert "port" in reason.lower()


def test_scope_out_of_scope_path_and_traversal():
    scope = ScopeProfile(
        primary_domain="http://127.0.0.1:8080/DVWA/",
        allowed_ips=["127.0.0.1"],
        allowed_ports=[8080],
        allowed_paths=["/DVWA/"],
        authorized_by_user=True,
    )

    # Path outside base path
    allowed, reason = scope.is_in_scope("http://127.0.0.1:8080/phpmyadmin/")
    assert allowed is False
    assert "outside permitted base paths" in reason

    # Path traversal attempt
    allowed, reason = scope.is_in_scope("http://127.0.0.1:8080/DVWA/../admin")
    assert allowed is False
    assert "path traversal" in reason.lower()


def test_scope_out_of_scope_redirect():
    scope = ScopeProfile(
        primary_domain="http://127.0.0.1:8080/DVWA/",
        allowed_ips=["127.0.0.1"],
        allowed_ports=[8080],
        allowed_paths=["/DVWA/"],
        authorized_by_user=True,
    )

    # In-scope internal redirect
    allowed, _ = scope.is_in_scope("http://127.0.0.1:8080/DVWA/login.php")
    assert allowed is True

    # Redirect to external or out-of-scope host
    allowed, _ = scope.is_in_scope("https://evil.com/phish")
    assert allowed is False

    # Redirect to same host on port 80
    allowed, _ = scope.is_in_scope("http://127.0.0.1:80/")
    assert allowed is False


def test_port_validation_range():
    # Valid port
    scope = ScopeProfile(
        primary_domain="127.0.0.1",
        allowed_ports=[8080, 8443, 80],
        authorized_by_user=True,
    )
    assert scope.allowed_ports == [8080, 8443, 80]

    # Invalid port 0
    with pytest.raises(ValueError):
        ScopeProfile(
            primary_domain="127.0.0.1",
            allowed_ports=[0],
            authorized_by_user=True,
        )

    # Invalid port > 65535
    with pytest.raises(ValueError):
        ScopeProfile(
            primary_domain="127.0.0.1",
            allowed_ports=[70000],
            authorized_by_user=True,
        )


def test_path_exclusions_dvwa():
    scope = ScopeProfile(
        primary_domain="http://127.0.0.1:8080/DVWA/",
        allowed_ips=["127.0.0.1"],
        allowed_ports=[8080],
        allowed_paths=["/DVWA/"],
        excluded_paths=["/logout", "/admin/delete"],
        authorized_by_user=True,
    )

    # In-scope path
    allowed, _ = scope.is_in_scope("http://127.0.0.1:8080/DVWA/vulnerabilities/sqli/")
    assert allowed is True

    # Excluded /logout path
    allowed, reason = scope.is_in_scope("http://127.0.0.1:8080/DVWA/logout.php")
    assert allowed is False
    assert "excluded path" in reason

    # Excluded /admin/delete path
    allowed, reason = scope.is_in_scope("http://127.0.0.1:8080/DVWA/admin/delete_user.php")
    assert allowed is False
    assert "excluded path" in reason


def test_legacy_scope_backward_compatibility():
    # Legacy scope with no allowed_ports specified
    scope = ScopeProfile(
        primary_domain="example.com",
        allowed_domains=["example.com"],
        authorized_by_user=True,
    )

    # Standard web ports 80 and 443 are permitted by default
    allowed, _ = scope.is_in_scope("http://example.com/index.html")
    assert allowed is True

    allowed, _ = scope.is_in_scope("https://example.com/dashboard")
    assert allowed is True

    # Non-standard custom ports like 8080 are NOT silently authorized
    allowed, reason = scope.is_in_scope("http://example.com:8080/test")
    assert allowed is False
    assert "not authorized" in reason.lower()


def test_redirect_to_unauthorized_port():
    scope = ScopeProfile(
        primary_domain="http://127.0.0.1:8080/DVWA/",
        allowed_ips=["127.0.0.1"],
        allowed_ports=[8080],
        allowed_paths=["/DVWA/"],
        authorized_by_user=True,
    )

    # Redirect to unauthorized port 9090
    allowed, reason = scope.is_in_scope("http://127.0.0.1:9090/callback")
    assert allowed is False
    assert "port" in reason.lower()

