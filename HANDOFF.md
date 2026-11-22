# DEVIXON — HANDOFF STATUS & ROADMAP

## Current State: Full URL Target Support & Multi-Application Isolation Complete & Verified

### 1. Canonical Target Model & URL Parser (`src/devixon/core/target.py`)
- **`CanonicalTarget` Model**:
  - `original_input`: Preserves exact user target input.
  - `scheme`: `"http"`, `"https"`, or `None` for bare domain/IP.
  - `hostname`: Clean, validated lowercased hostname or IP.
  - `port`: Explicit port or default port (HTTP: 80, HTTPS: 443).
  - `base_path`: Directory base path (e.g. `/DVWA/`, `/app/`, `/`).
  - `canonical_url`: Normalized URL preserving explicit ports and directory paths.
  - `target_type`: `"URL"`, `"DOMAIN"`, or `"IP"`.
  - `service_identity`: Unique service identifier combining `scheme + hostname + port` (e.g. `http://127.0.0.1:8080` vs `http://127.0.0.1:80`).
- **Validation**:
  - Pydantic `HttpUrl` validation via `TypeAdapter(HttpUrl).validate_python`.
  - Base-path traversal detection rejecting attempts like `/../` and `/DVWA/../secret`.
  - Preservation of explicit ports and base paths without silent stripping.

### 2. Scope Engine Enhancements (`src/devixon/core/scope.py`)
- **Port Policy Enforcement**:
  - Validates ports against `allowed_ports` or primary target port constraints.
  - Out-of-scope ports (such as port 80 during an 8080 scan) are strictly rejected.
- **Base Path & Path Traversal Confinement**:
  - Confinements paths to `allowed_paths` and target `base_path`.
  - Detects and rejects path traversal sequences (`/../`, `/..`).
- **Redirect Validation**:
  - Validates redirect destinations against authorized domain, IP, port, and path rules.
- **Dynamic Scopes**:
  - `_load_scope()` in `recon.py` automatically configures `primary_domain`, `allowed_ips`, `allowed_ports`, and `allowed_paths` from `CanonicalTarget`.

### 3. Pipeline Multi-Stage Integration
- **`STAGE_00` Scope Validation**: Enforces full URL validation against `allowed_ports` and `allowed_paths`.
- **`STAGE_02` Subdomain Discovery**: Accurately recognizes localhost/IP URL targets and tags subdomain enumeration as `NOT_APPLICABLE`.
- **`STAGE_05` Live Host Discovery**: Directly probes `ctx.target_model.canonical_url` and records `LiveHost` keyed to `service_identity`.
- **`STAGE_06` Service Discovery**: Restricts port probing to in-scope ports (`ctx.target_model.port` / `allowed_ports`), preventing probe leakage into CTFd on port 80.
- **`STAGE_09` Crawler**: Seeds from `ctx.target_model.canonical_url`, confines crawling strictly within `base_path` on the allowed port, and classifies external/cross-port links as `is_internal=False`.
- **`STAGE_10` Endpoints**: Extracts endpoints under the authorized `base_path` and maps to asset without port confusion.
- **`STAGE_12` APIs & `STAGE_13` Content Discovery**: Prepends `base_path` to discovery wordlists (e.g. `/DVWA/admin`, `/DVWA/robots.txt`) and enforces scope before every request.
- **`STAGE_17` & Reports**: Sanitizes output file names across Windows/POSIX environments and displays exact `assessment.target` in reports.

### 4. CLI Enhancements
- CLI help description across all recon commands updated to:
  `"Target domain, IP address, or full HTTP/HTTPS URL."`
- `devixon scope create` enhanced with `--allowed-ports` and `--allowed-paths`.
- `devixon scope show` displays configured `Allowed Ports` and `Allowed Paths`.

### 5. Test Suite Verification
- **34 / 34 Tests Passing** in `pytest -v` across all test suites:
  - `tests/unit/test_target.py`: Tests domain-only, IPv4, HTTP with custom port, HTTPS, URL with base path, query strings, invalid URLs, traversal attempts, normalization, and scope enforcement.
  - `tests/integration/test_dvwa_target_e2e.py`: End-to-end integration test simulating CTFd and DVWA co-hosted on `127.0.0.1` on different ports. Confirms requests reach port 8080, crawl starts at `/DVWA/`, CTFd routes on port 80 never appear in endpoints or live hosts, and report displays exact target URL.
  - All existing unit, security, crawler, CVSS, database, and report tests pass without regression.
- **9 / 9 Tests Passing** in `devixon self-test`.
