"""
Centralized typed exceptions for DEVIXON framework.
"""

from typing import Optional, Dict, Any
from datetime import datetime, timezone


class DevixonError(Exception):
    """Base exception for all DEVIXON errors."""

    def __init__(
        self,
        message: str,
        code: str = "ERR_GENERAL",
        technical_details: Optional[str] = None,
        stage: Optional[str] = None,
        tool: Optional[str] = None,
        recoverable: bool = False,
        suggested_action: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.technical_details = technical_details
        self.stage = stage
        self.tool = tool
        self.recoverable = recoverable
        self.suggested_action = suggested_action
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.code,
            "message": self.message,
            "technical_details": self.technical_details,
            "stage": self.stage,
            "tool": self.tool,
            "recoverable": self.recoverable,
            "suggested_action": self.suggested_action,
            "timestamp": self.timestamp,
        }


class ConfigurationError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_CONFIG", **kwargs)


class ScopeViolationError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_SCOPE_VIOLATION", recoverable=False, **kwargs)


class TargetValidationError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_TARGET_VALIDATION", recoverable=False, **kwargs)


class ToolMissingError(DevixonError):
    def __init__(self, tool_name: str, **kwargs):
        msg = f"External tool '{tool_name}' is not found in PATH."
        suggestion = kwargs.pop("suggested_action", f"Install '{tool_name}' or rely on native Python fallback.")
        super().__init__(msg, code="ERR_TOOL_MISSING", tool=tool_name, recoverable=True, suggested_action=suggestion, **kwargs)


class ToolExecutionError(DevixonError):
    def __init__(self, message: str, tool_name: Optional[str] = None, **kwargs):
        super().__init__(message, code="ERR_TOOL_EXECUTION", tool=tool_name, recoverable=True, **kwargs)


class ToolTimeoutError(DevixonError):
    def __init__(self, tool_name: str, timeout_seconds: float, **kwargs):
        msg = f"Tool '{tool_name}' timed out after {timeout_seconds} seconds."
        super().__init__(msg, code="ERR_TOOL_TIMEOUT", tool=tool_name, recoverable=True, **kwargs)


class NetworkError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_NETWORK", recoverable=True, **kwargs)


class DNSResolutionError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_DNS_RESOLUTION", recoverable=True, **kwargs)


class HTTPProbeError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_HTTP_PROBE", recoverable=True, **kwargs)


class DatabaseError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_DATABASE", recoverable=False, **kwargs)


class DataValidationError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_DATA_VALIDATION", recoverable=False, **kwargs)


class AIProviderError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_AI_PROVIDER", recoverable=True, **kwargs)


class ReportGenerationError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_REPORT_GEN", recoverable=False, **kwargs)


class ScanCancelledError(DevixonError):
    def __init__(self, message: str = "Scan was cancelled by user.", **kwargs):
        super().__init__(message, code="ERR_SCAN_CANCELLED", recoverable=False, **kwargs)


class PermissionError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_PERMISSION", recoverable=False, **kwargs)


class DependencyError(DevixonError):
    def __init__(self, message: str, **kwargs):
        super().__init__(message, code="ERR_DEPENDENCY", recoverable=False, **kwargs)
