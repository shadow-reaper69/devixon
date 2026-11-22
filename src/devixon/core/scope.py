"""
DEVIXON Scope Engine & Authorization Verification.
Strictly governs target validation, domain matching, CIDR ranges, port constraints,
base paths, and path exclusions.
"""

import ipaddress
import posixpath
import re
from typing import List, Optional, Tuple, Set
from urllib.parse import urlparse, urlsplit
from pydantic import BaseModel, Field, field_validator
from devixon.core.exceptions import ScopeViolationError, TargetValidationError
from devixon.core.target import CanonicalTarget, parse_canonical_target


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
    allowed_ports: List[int] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)
    rate_limit: int = 10  # reqs/sec
    max_concurrency: int = 5
    timeout: int = 15  # seconds
    authorized_by_user: bool = False
    scope_notes: Optional[str] = None

    @field_validator("allowed_ports")
    @classmethod
    def validate_allowed_ports(cls, ports: List[int]) -> List[int]:
        for p in ports:
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} is invalid. Must be between 1 and 65535.")
        return ports

    def validate_authorization(self) -> None:
        """Enforces that explicit user authorization has been recorded."""
        if not self.authorized_by_user:
            raise ScopeViolationError(
                f"Scope '{self.name}' has NOT been confirmed as authorized by the user. "
                "Explicit authorization confirmation is required before any active network scans."
            )

    def is_in_scope(
        self,
        target: str,
        path: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Determines whether a target (URL, hostname, or IP), optional path, and optional port is within scope.
        Validates host, port, path prefix, path traversal, and exclusions.
        Returns: (is_allowed: bool, reason: str)
        """
        # If target is a full URL, extract components
        parsed_target = None
        target_path = path
        target_port = port

        if "://" in target:
            try:
                parsed_target = urlsplit(target)
                clean_host = parsed_target.hostname.lower() if parsed_target.hostname else ""
                if target_port is None and parsed_target.port:
                    target_port = parsed_target.port
                elif target_port is None:
                    target_port = 443 if parsed_target.scheme == "https" else 80
                if target_path is None:
                    target_path = parsed_target.path
            except Exception as e:
                return False, f"Invalid URL target format: {e}"
        elif ":" in target and not target.count(":") > 1 and "/" not in target:
            parts = target.split(":")
            clean_host = parts[0].strip().lower()
            try:
                if target_port is None:
                    target_port = int(parts[1])
            except ValueError:
                return False, f"Invalid port in target: {target}"
        else:
            try:
                clean_host = normalize_target(target)
            except TargetValidationError as e:
                return False, f"Invalid target format: {e.message}"

        if not clean_host:
            return False, "Empty or invalid target hostname."

        # Parse primary domain to understand primary port and base path if specified
        primary_info = None
        try:
            primary_info = parse_canonical_target(self.primary_domain)
            primary_host = primary_info.hostname.lower()
            primary_port = primary_info.port
            primary_base_path = primary_info.base_path
        except Exception:
            primary_host = normalize_target(self.primary_domain)
            primary_port = None
            primary_base_path = "/"

        # 1. Check explicit excluded targets first
        for excl in self.excluded_targets:
            excl_clean = excl.strip().lower()
            if clean_host == excl_clean:
                return False, f"Target '{clean_host}' is explicitly in excluded_targets list."
            if excl_clean.startswith("*.") and (clean_host.endswith(excl_clean[1:]) or clean_host == excl_clean[2:]):
                return False, f"Target '{clean_host}' matches excluded wildcard '{excl_clean}'."

        # 2. Check Port Policy
        if target_port is not None:
            # If explicit allowed_ports are set, port must be in allowed_ports
            if self.allowed_ports:
                if target_port not in self.allowed_ports:
                    return False, f"Port {target_port} is not in allowed_ports list: {self.allowed_ports}."
            # If no allowed_ports, but primary target specified a specific port (e.g. 8080), restrict to that port
            elif primary_port is not None and primary_info:
                if target_port != primary_port:
                    return False, f"Port {target_port} does not match target application port {primary_port}."
            else:
                # Backward-compatible default: when allowed_ports is empty, only standard web ports (80, 443) are allowed
                if target_port not in (80, 443):
                    return False, f"Port {target_port} is not authorized. Standard web ports (80, 443) permitted by default; use --allowed-ports to authorize custom ports."

        # 3. Check Path Validations and Exclusions
        if target_path:
            # Check for path traversal attempts (e.g. /DVWA/../secret)
            if "/../" in target_path or target_path.endswith("/..") or "/.." in target_path:
                return False, f"Path traversal attempt detected in path: '{target_path}'."

            norm_path = posixpath.normpath(target_path)
            if not norm_path.startswith("/"):
                norm_path = "/" + norm_path

            # Check explicit excluded paths
            for excl_p in self.excluded_paths:
                if excl_p.lower() in norm_path.lower():
                    return False, f"Path '{target_path}' contains excluded path '{excl_p}'."

            # Check allowed paths / base path confinement
            effective_allowed_paths = list(self.allowed_paths)
            if primary_base_path and primary_base_path != "/" and primary_base_path not in effective_allowed_paths:
                effective_allowed_paths.append(primary_base_path)

            if effective_allowed_paths:
                # Path must start with at least one allowed path prefix
                matched_prefix = False
                for p_prefix in effective_allowed_paths:
                    norm_prefix = posixpath.normpath(p_prefix)
                    if norm_path == norm_prefix or norm_path.startswith(norm_prefix.rstrip("/") + "/"):
                        matched_prefix = True
                        break
                if not matched_prefix:
                    return False, f"Path '{norm_path}' is outside permitted base paths: {effective_allowed_paths}."

        # 4. Check if target is an IP address
        is_ip = False
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            is_ip = True
        except ValueError:
            is_ip = False

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
            # If primary domain matches this IP
            if clean_host == primary_host:
                return True, "IP matches primary target."
            return False, f"IP '{clean_host}' is not in allowed IP list or networks."

        # 5. Target is a domain/hostname
        if clean_host == primary_host:
            return True, f"Hostname matches primary domain '{primary_host}'."

        # Check allowed domains list
        candidates = [primary_host] + [d.lower().strip() for d in self.allowed_domains]
        for pattern in candidates:
            if pattern.startswith("*."):
                root = pattern[2:]
                if clean_host == root or clean_host.endswith("." + root):
                    return True, f"Hostname '{clean_host}' matches allowed wildcard '{pattern}'."
            else:
                if clean_host == pattern:
                    return True, f"Hostname '{clean_host}' matches allowed domain '{pattern}'."

        return False, f"Hostname '{clean_host}' is not in allowed scope."
