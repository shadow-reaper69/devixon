# DEVIXON — ERROR HANDLING & RESILIENCE SPECIFICATION

## Hierarchy of Typed Exceptions
All exceptions inherit from `DevixonError`:
- `ConfigurationError`: Invalid config file or settings
- `ScopeViolationError`: Target or operation violates authorized boundaries
- `TargetValidationError`: Target input cannot be parsed or resolved
- `ToolMissingError`: External tool binary not found on PATH
- `ToolExecutionError`: External tool crashed or exited with non-zero status
- `ToolTimeoutError`: Process execution exceeded configured timeout
- `NetworkError`: General network connectivity error
- `DNSResolutionError`: Domain resolution failure
- `HTTPProbeError`: HTTP connection refused or TLS handshake failure
- `DatabaseError`: Transaction rollback or database integrity fault
- `DataValidationError`: Data schema parsing error
- `AIProviderError`: AI API rate-limit, key failure, or network error
- `ReportGenerationError`: Template rendering or report export failure
- `ScanCancelledError`: User aborted scan with SIGINT / cancel command
- `DependencyError`: Missing Python dependency

## Self-Recovery Principles
- Missing tools trigger `[SKIP]` warnings; pipeline continues with native fallbacks.
- Timeouts kill child process trees and log timeout metrics without terminating the assessment.
- Rate limits (HTTP 429) trigger bounded exponential backoff with jitter and retry-after header parsing.
