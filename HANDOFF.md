# DEVIXON — HANDOFF STATUS & ROADMAP

## Current State: Complete & Verified

### 1. Architectural Foundation
- **Packaging**: Standard `pyproject.toml` configuration with console entrypoint `devixon = "devixon.cli.main:app"`.
- **Scope Engine**: `devixon.core.scope.ScopeProfile` strictly validates wildcards (`*.example.com`), exact hostnames, CIDR ranges, excluded paths, and mandatory user authorization gates before any active probe.
- **Typed Exceptions**: 17 domain-specific exceptions inheriting from `DevixonError`, providing error codes, technical details, recoverability, and remediation recommendations.
- **Resilient Process Runner**: `devixon.core.runner.run_subprocess` executes external processes without `shell=True`, enforcing strict argument sanitization, timeouts, output bounds, and child process tree termination.
- **Database**: SQLite with SQLAlchemy 2.0 ORM models (`Assessment`, `Asset`, `Service`, `Endpoint`, `Finding`, `Evidence`, `ScanStage`) with foreign keys and indexes.

### 2. Reconnaissance Pipeline
- **18-Stage Modular Architecture**:
  - `STAGE_00`: Scope & Authorization Validation
  - `STAGE_01`: Passive OSINT (crt.sh Certificate Transparency)
  - `STAGE_02`: Subdomain Discovery (Subfinder adapter + native fallback)
  - `STAGE_03`: DNS Intelligence (A, AAAA, CNAME, MX, TXT via dnspython)
  - `STAGE_04`: Asset Correlation & Inventory
  - `STAGE_05`: Live Host Discovery (httpx prober + headers & title extraction)
  - `STAGE_06`: Service Discovery (safe top web/infra ports)
  - `STAGE_07`: Technology Fingerprinting (Wappalyzer-like headers/meta heuristics)
  - `STAGE_08`: URL Intelligence (Web archive querying)
  - `STAGE_09`: Web Crawling (Scope-governed crawler with depth and count bounds)
  - `STAGE_10`: Endpoint & Parameter Extraction
  - `STAGE_11`: JavaScript Intelligence (Scoped JS analysis, route discovery, masked secret detection)
  - `STAGE_12`: API Reconnaissance (OpenAPI, Swagger, GraphQL endpoint checks)
  - `STAGE_13`: Content & Sensitive File Discovery (`robots.txt`, `security.txt`, `.git/HEAD`, `.env`)
  - `STAGE_14`: Security Posture Checks (HSTS, CSP, X-Content-Type-Options, CORS)
  - `STAGE_15`: Evidence Normalization & Finding Persistence (SHA256 evidence hashing)
  - `STAGE_16`: AI Security Analysis (Provider-independent, offline fallback, prompt injection quarantine)
  - `STAGE_17`: Final Report Generation (HTML, Markdown, JSON, CSV)

### 3. Finding Validation & Security
- **Multi-State Verification**: `CONFIRMED`, `LIKELY`, `NEEDS_REVIEW`, `INFORMATIONAL`, `FALSE_POSITIVE`, `FIXED`.
- **Manual Verification Checklists**: Dedicated guides for XSS, SQLi, SSRF, IDOR, Auth Flaws, and Misconfigurations.
- **Deterministic CVSS v3.1 Calculator**: Pure algorithmic calculation without hallucination.

### 4. Verification & Testing
- **14/14 Pytest Unit & Boundary Tests Passing**.
- **9/9 CLI Self-Tests Passing** via `devixon self-test`.
- **Operational CLI Verification**: `devixon doctor`, `devixon setup`, `devixon scope`, `devixon recon`, `devixon assets`, `devixon findings`, and `devixon report` fully operational.
