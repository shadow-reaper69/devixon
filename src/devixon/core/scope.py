"""
DEVIXON Scope Engine & Authorization Verification.
Strictly governs target validation, domain matching, CIDR ranges, and path exclusions.
"""

import ipaddress
import re
from typing import List, Optional, Tuple, Set
from urllib.parse import urlparse
from pydantic import BaseModel, Field
from devixon.core.exceptions import ScopeViolationError, TargetValidationError


def normalize_target(target: str) -> str:
    """
    Normalizes a user-supplied target into a clean hostname or IP string.
    Example: 'https://example.com:8443/test?a=1' -> 'example.com'
    """
    target = target.strip()
    if not target:
        raise TargetValidationError("Target cannot be empty.")

    # If it contains a protocol or scheme, parse with urlparse
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname
        if not host:
            raise TargetValidationError(f"Could not parse valid hostname from URL: {target}")
        return host.lower()

    # If it has a port or path without protocol
    if "/" in target:
        target = target.split("/")[0]
    if ":" in target and not target.count(":") > 1:  # Not an IPv6 address
        target = target.split(":")[0]

    target = target.strip().lower()
    # Check valid characters (allow leading wildcard *. for domain rules)
    if not re.match(r"^(\*\.)?[a-zA-Z0-9_\-\.\:]+$", target):
        raise TargetValidationError(f"Target contains invalid characters: {target}")

    return target


class ScopeProfile(BaseModel):
    assessment_id: Optional[str] = None
    name: str = "Default Scope"
    primary_domain: str
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_ips: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)
    rate_limit: int = 10  # reqs/sec
    max_concurrency: int = 5
    timeout: int = 15  # seconds
    authorized_by_user: bool = False
    scope_notes: Optional[str] = None

    def validate_authorization(self) -> None:
        """Enforces that explicit user authorization has been recorded."""
        if not self.authorized_by_user:
            raise ScopeViolationError(
                f"Scope '{self.name}' has NOT been confirmed as authorized by the user. "
                "Explicit authorization confirmation is required before any active network scans."
            )

    def is_in_scope(self, target: str, path: Optional[str] = None) -> Tuple[bool, str]:
        """
        Determines whether a target (hostname or IP) and optional URL path is within scope.
        Returns: (is_allowed: bool, reason: str)
        """
        try:
            clean_host = normalize_target(target)
        except TargetValidationError as e:
            return False, f"Invalid target format: {e.message}"

        # 1. Check explicit excluded targets first
        for excl in self.excluded_targets:
            excl_clean = excl.strip().lower()
            if clean_host == excl_clean:
                return False, f"Target '{clean_host}' is explicitly in excluded_targets list."
            if excl_clean.startswith("*.") and (clean_host.endswith(excl_clean[1:]) or clean_host == excl_clean[2:]):
                return False, f"Target '{clean_host}' matches excluded wildcard '{excl_clean}'."

        # 2. Check path exclusions
        if path:
            norm_path = path.lower()
            for excl_p in self.excluded_paths:
                if excl_p.lower() in norm_path:
                    return False, f"Path '{path}' contains excluded path '{excl_p}'."

        # 3. Check if target is an IP address
        is_ip = False
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            is_ip = True
        except ValueError:
            is_ip = False

        norm_primary = normalize_target(self.primary_domain)

        if is_ip:
            # Check against allowed IPs and CIDRs
            for allowed_ip_spec in self.allowed_ips:
                try:
                    clean_allowed_ip = normalize_target(allowed_ip_spec) if "/" not in allowed_ip_spec else allowed_ip_spec
                    if "/" in clean_allowed_ip:
                        network = ipaddress.ip_network(clean_allowed_ip, strict=False)
                        if ip_obj in network:
                            return True, f"IP '{clean_host}' is within allowed network '{clean_allowed_ip}'."
                    else:
                        allowed_single = ipaddress.ip_address(clean_allowed_ip)
                        if ip_obj == allowed_single:
                            return True, f"IP '{clean_host}' matches allowed IP '{clean_allowed_ip}'."
                except ValueError:
                    continue
            # If primary domain is this IP
            if clean_host == norm_primary:
                return True, f"IP matches primary target."
            return False, f"IP '{clean_host}' is not in allowed IP list or networks."

        # 4. Target is a domain/hostname
        # Check against primary domain
        clean_primary = norm_primary
        if clean_host == clean_primary:
            return True, f"Hostname matches primary domain '{clean_primary}'."

        # Check allowed domains list
        candidates = [clean_primary] + [d.lower().strip() for d in self.allowed_domains]
        for pattern in candidates:
            if pattern.startswith("*."):
                root = pattern[2:]
                if clean_host == root or clean_host.endswith("." + root):
                    return True, f"Hostname '{clean_host}' matches allowed wildcard '{pattern}'."
            else:
                if clean_host == pattern:
                    return True, f"Hostname '{clean_host}' matches allowed domain '{pattern}'."

        return False, f"Hostname '{clean_host}' is not in allowed scope."
