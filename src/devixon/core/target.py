"""
DEVIXON Canonical Target Model & URL Parser.
Provides robust parsing and validation for domains, IP addresses, and full HTTP/HTTPS URLs with custom ports and base paths.
"""

import ipaddress
import posixpath
import re
from typing import Optional
from urllib.parse import urlsplit
from pydantic import BaseModel, Field, HttpUrl, TypeAdapter, ValidationError
from devixon.core.exceptions import TargetValidationError


class CanonicalTarget(BaseModel):
    original_input: str
    scheme: Optional[str] = None  # "http", "https", or None for bare domain/IP
    hostname: str
    port: Optional[int] = None  # e.g. 80, 443, 8080
    base_path: str = "/"  # e.g. "/DVWA/", "/app/", "/"
    canonical_url: str
    target_type: str  # "URL", "DOMAIN", "IP"
    query: Optional[str] = None

    @property
    def service_identity(self) -> str:
        """
        Unique service identity combining scheme + hostname + port.
        Separates applications on the same IP (e.g., CTFd on 80 vs DVWA on 8080).
        """
        eff_scheme = self.effective_scheme
        eff_port = self.effective_port
        return f"{eff_scheme}://{self.hostname}:{eff_port}"

    @property
    def effective_scheme(self) -> str:
        if self.scheme:
            return self.scheme
        if self.hostname in ("localhost", "127.0.0.1") or self.hostname.startswith("192.168.") or self.hostname.startswith("10."):
            return "http"
        return "https"

    @property
    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        return 80 if self.effective_scheme == "http" else 443

    @property
    def effective_url(self) -> str:
        """Returns the full accessible URL including base path."""
        return self.canonical_url


def parse_canonical_target(target: str) -> CanonicalTarget:
    """
    Parses and validates a user-supplied target into a CanonicalTarget model.
    Supports:
      - example.com
      - 127.0.0.1
      - http://127.0.0.1:8080/DVWA/
      - https://example.com/app/
      - 127.0.0.1:8080
    """
    raw = target.strip()
    if not raw:
        raise TargetValidationError("Target cannot be empty.")

    # Check for path traversal attempts in raw input
    if "/../" in raw or raw.endswith("/..") or "/.." in raw:
        raise TargetValidationError(f"Base-path traversal attempt detected in target: {raw}")

    # Determine if scheme is present
    has_scheme = "://" in raw
    explicit_port = False

    if has_scheme:
        split_parts = raw.split("://", 1)
        scheme_candidate = split_parts[0].lower()
        if scheme_candidate not in ("http", "https"):
            raise TargetValidationError(f"Unsupported scheme '{scheme_candidate}'. DEVIXON supports HTTP and HTTPS targets.")
        url_to_parse = raw
    else:
        # Check if input has a port or path
        # E.g. "127.0.0.1:8080/DVWA/" or "example.com/app"
        if "/" in raw or (":" in raw and not raw.count(":") > 1):
            first_segment = raw.split("/")[0]
            host_candidate = first_segment.split(":")[0].lower()
            if host_candidate in ("localhost", "127.0.0.1") or host_candidate.startswith("192.168.") or host_candidate.startswith("10."):
                url_to_parse = f"http://{raw}"
            else:
                url_to_parse = f"https://{raw}"
        else:
            url_to_parse = None

    if url_to_parse:
        # Pydantic URL validation
        try:
            TypeAdapter(HttpUrl).validate_python(url_to_parse)
        except ValidationError as ve:
            raise TargetValidationError(f"Invalid target URL structure: {ve}")
        except Exception as e:
            raise TargetValidationError(f"Failed to validate target URL '{raw}': {e}")

        try:
            parsed = urlsplit(url_to_parse)
        except Exception as e:
            raise TargetValidationError(f"Failed to parse target URL '{raw}': {e}")

        hostname = parsed.hostname
        if not hostname:
            raise TargetValidationError(f"Could not parse valid hostname from '{raw}'.")
        hostname = hostname.lower()

        # Validate hostname characters
        if not re.match(r"^(\*\.)?[a-zA-Z0-9_\-\.]+$", hostname):
            raise TargetValidationError(f"Target contains invalid hostname characters: {hostname}")

        scheme = parsed.scheme.lower() if parsed.scheme else ("http" if hostname in ("localhost", "127.0.0.1") else "https")

        # Determine port
        if parsed.port is not None:
            explicit_port = True
            port = parsed.port
            if not (1 <= port <= 65535):
                raise TargetValidationError(f"Invalid port number {port}. Must be between 1 and 65535.")
        else:
            # Default ports: HTTP: 80, HTTPS: 443
            port = 443 if scheme == "https" else 80

        # Normalize base path: preserve directory structure, strip query/fragment
        raw_path = parsed.path or "/"
        clean_path = re.sub(r"/+", "/", raw_path)
        norm_path = posixpath.normpath(clean_path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        while norm_path.startswith("//"):
            norm_path = norm_path[1:]
        if raw_path.endswith("/") and not norm_path.endswith("/"):
            norm_path += "/"
        if norm_path == ".":
            norm_path = "/"

        # Traversal check on normalized path
        if "/../" in norm_path or norm_path.startswith("/.."):
            raise TargetValidationError(f"Path traversal detected in base path: {raw_path}")

        base_path = norm_path

        # Determine target type
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        target_type = "URL" if (has_scheme or "/" in raw) else ("IP" if is_ip else "DOMAIN")

        # Construct canonical URL
        # Do not silently remove port if explicitly provided in raw input or non-default
        if explicit_port:
            netloc = f"{hostname}:{port}"
        elif (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            netloc = f"{hostname}:{port}"
        else:
            netloc = hostname

        canonical_url = f"{scheme}://{netloc}{base_path}"

        return CanonicalTarget(
            original_input=raw,
            scheme=scheme if has_scheme else None,
            hostname=hostname,
            port=port if (has_scheme or explicit_port) else None,
            base_path=base_path,
            canonical_url=canonical_url,
            target_type=target_type,
            query=parsed.query if parsed.query else None,
        )

    # Pure Domain or IP without scheme, port, or path
    hostname = raw.lower()
    if ":" in hostname and not hostname.count(":") > 1:
        hostname = hostname.split(":")[0]

    if not re.match(r"^(\*\.)?[a-zA-Z0-9_\-\.]+$", hostname):
        raise TargetValidationError(f"Target contains invalid hostname characters: {raw}")

    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    target_type = "IP" if is_ip else "DOMAIN"
    scheme = "http" if is_ip and hostname in ("127.0.0.1", "localhost") else "https"
    port = 80 if scheme == "http" else 443
    base_path = "/"
    canonical_url = f"{scheme}://{hostname}{base_path}"

    # Pydantic URL validation on constructed canonical url
    try:
        TypeAdapter(HttpUrl).validate_python(canonical_url)
    except Exception as e:
        raise TargetValidationError(f"Invalid canonical URL generated for '{raw}': {e}")

    return CanonicalTarget(
        original_input=raw,
        scheme=None,  # No explicit scheme provided
        hostname=hostname,
        port=None,    # No explicit port provided
        base_path=base_path,
        canonical_url=canonical_url,
        target_type=target_type,
    )
