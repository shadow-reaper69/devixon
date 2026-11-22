# DEVIXON — HANDOFF STATUS & ROADMAP

## Current State: Port-Aware Scope Authorization & Full URL Target Support Complete & Verified

### 1. Root Cause Analysis & Resolution of Discrepancy
- **Identified Issue**:
  - Previously, `Stage05LiveHosts` ran before `Stage06ServiceDiscovery`. When target was an IP (e.g., `127.0.0.1`), Stage 05 only probed default ports (80/443), while port 8080 was only discovered afterward in raw TCP by Stage 06.
  - Stage 06 did not probe HTTP/HTTPS and never populated `ctx.live_hosts`.
  - Because `ctx.live_hosts` remained empty, all downstream stages (Technology Fingerprinting, Crawler, Endpoints, JavaScript Intelligence, APIs, FFUF, Posture Checks) had 0 target URLs to evaluate, cascading into 0 findings, 0 endpoints, and 0 paths.
  - In `Stage05LiveHosts`, network exceptions were silently swallowed.
- **Resolution**:
  - Reordered pipeline stages: `Stage06ServiceDiscovery` now executes *before* `Stage05LiveHosts`.
  - `Stage06ServiceDiscovery` performs TCP port probing on authorized ports, then automatically qualifies open ports with `_probe_http_service()` to identify HTTP/HTTPS services, persisting `LiveHost` records and populating `ctx.live_hosts`.
  - `Stage05LiveHosts` probes `ctx.target_model.canonical_url`, plus any authorized ports in `scope.allowed_ports` and `ctx.open_ports`.
  - Explicit network exception handling (`httpx.ConnectError`, `httpx.ConnectTimeout`, `httpx.HTTPError`) logs debug details rather than swallowing errors silently.

### 2. Port-Aware Scope Authorization (`src/devixon/core/scope.py`, `src/devixon/cli/commands/scope.py`)
- **Port Validation & Enforcement**:
  - Added strict port validation requiring integer values between 1 and 65535 (`1 <= port <= 65535`).
  - Added CLI support: `devixon scope create --allowed-ports 8080` (with aliases `--domain`/`--target`, `--authorized`/`--authorized-by-user`, and `--exclude-paths`/`--excluded-paths`).
  - Updated `devixon scope show <name>` to display `Primary Target`, `Authorization Status`, `Allowed Domains`, `Allowed IPs`, `Allowed Ports`, `Excluded Targets`, and `Excluded Paths`.
  - `ScopeProfile.is_in_scope()` enforces that when `allowed_ports` is defined, only explicitly listed ports are authorized.
  - Backward compatibility: when `allowed_ports` is empty, standard web ports (80, 443) are authorized for domain/IP targets, or the explicit port from a full URL target. Discovered ports outside authorized scope are rejected from active probing.
  - Path exclusions (e.g. `/logout`, `/admin/delete`) are strictly enforced, marking links as out-of-scope and blocking them from crawler queuing or endpoint storage.

### 3. Pipeline Integration & Downstream Propagation
- **Stage 00 (Scope Validation)**: Validates target URL, port, base path, and path traversal prior to any scan activities.
- **Stage 06 (Service Discovery)**: Confines port scans to authorized ports and identifies web services.
- **Stage 05 (Live Host Discovery)**: Successfully detects `http://127.0.0.1:8080/DVWA/` (HTTP 200) and persists it.
- **Stage 07–16 (Downstream Stages)**: Crawler, Endpoint Extraction, JS Intelligence, FFUF, and Security Posture receive `http://127.0.0.1:8080/DVWA/` and respect path exclusions.
- **Stage 17 (Reporting)**: Generates sanitized report filenames across Windows and POSIX systems and displays exact target URLs.

### 4. Test Suite Verification
- **39 / 39 Tests Passing** (38 passed, 1 cleanly skipped when live DVWA is offline):
  - `tests/unit/test_target.py` (16 tests): Tests domain-only, IPv4, custom HTTP/HTTPS ports, base paths, query strings, traversal attempts, normalization, port ranges, DVWA path exclusions, and backward compatibility.
  - `tests/unit/test_scope.py` (5 tests): Scope domain, CIDR IP, exclusions, and authorization enforcement.
  - `tests/security/test_scope_boundaries.py` (3 tests): Scope boundary rejections and injection/traversal defenses.
  - `tests/integration/test_dvwa_target_e2e.py` (2 tests): Simulates CTFd and DVWA co-hosted on `127.0.0.1` on different ports with `/DVWA/` base path and `/logout` exclusion. Confirms DVWA is crawled, CTFd routes are isolated, excluded paths are rejected, and reports show exact target URL. Live DVWA test cleanly skips when DVWA is not active.
  - `tests/integration/test_recon_pipeline_e2e.py` (1 test): Full multi-stage pipeline run against local HTTP server.
  - All unit tests for crawler, CVSS, database, recon models, and reports pass without regression.
- **9 / 9 Tests Passing** in `devixon self-test`.

