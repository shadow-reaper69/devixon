# DEVIXON
### AI-Assisted Reconnaissance & Web Security Assessment Framework

[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-14%20passed-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-teal.svg)]()

**DEVIXON** is a terminal-first security assessment and attack surface mapping framework engineered for authorized penetration testing, bug bounty researchers, and security teams.

DEVIXON prioritizes **evidence over speculation**, **strict scope enforcement**, and **non-destructive posture auditing**. It operates completely offline with native Python fallbacks, and includes an advisory, prompt-injection quarantined AI subsystem for attack surface prioritization.

---

## 📑 Table of Contents
1. [Core Features](#-core-features)
2. [Architecture Overview](#-architecture-overview)
3. [18-Stage Reconnaissance Pipeline](#-18-stage-reconnaissance-pipeline)
4. [Installation & Setup](#-installation--setup)
5. [Step-by-Step Usage Guide](#-step-by-step-usage-guide)
6. [Complete CLI Reference](#-complete-cli-reference)
7. [Finding Validation & Manual Checklists](#-finding-validation--manual-checklists)
8. [Report Generation](#-report-generation)
9. [Running Tests](#-running-tests)
10. [Ethics & Legal Protocol](#-ethics--legal-protocol)

---

## ⚡ Core Features

- **Strict Scope Engine**: Validates every host, IP, wildcard (`*.example.com`), CIDR (`192.168.1.0/24`), and excluded path before issuing any probe.
- **Mandatory Authorization Gate**: Requires explicit confirmation (`--authorized`) before any active scan.
- **Graceful Degradation**: External binaries (`subfinder`, `katana`, `nmap`, `ffuf`, `gau`) are optional adapters. Built-in native Python fallbacks ensure full functionality out of the box on any system.
- **Persistent Data Store**: SQLite backend powered by SQLAlchemy 2.0 with foreign keys, relational indexing, and resume support.
- **Evidence-Backed Findings**: Distinguishes between verified vulnerabilities, hypotheses, and informational items. Pure mathematical CVSS v3.1 scoring.
- **AI Security Analyst**: Agnostic integration with OpenAI-compatible or local LLMs with prompt-injection isolation and credential masking. Works 100% offline when AI is disabled.
- **Professional Reporting**: Generates client-ready HTML reports (dark theme), HackerOne/Bugcrowd Markdown, JSON, and CSV.

---

## 🏗 Architecture Overview

```
                        +----------------------------+
                        |      CLI (Typer + Rich)    |
                        +--------------+-------------+
                                       |
                +----------------------+----------------------+
                |                      |                      |
     +----------v----------+ +---------v----------+ +---------v----------+
     | Scope Engine        | | Pipeline Engine    | | Finding Validation |
     | - Target Normalizer | | - 18 Async Stages  | | - Evidence Checker |
     | - Wildcard / CIDR   | | - Tool Adapters    | | - CVSS Calculator  |
     | - Excluded Routes   | | - Native Fallbacks | | - Verification DB  |
     +---------------------+ +---------+----------+ +--------------------+
                                       |
                   +-------------------+-------------------+
                   |                   |                   |
        +----------v-------+ +---------v--------+ +--------v---------+
        | Database (SQLite)| | AI Engine        | | Reporting Engine |
        | - SQLAlchemy 2.0 | | - Agnostic Client| | - Jinja2 HTML    |
        | - 7 Core Tables  | | - Pydantic Output| | - Markdown / CSV |
        | - Foreign Keys   | | - Redaction Guard| | - JSON Artifacts |
        +------------------+ +------------------+ +------------------+
```

---

## 🔄 18-Stage Reconnaissance Pipeline

DEVIXON structures assessments into independent, resumable stages:

| Stage | Name | Description |
| :--- | :--- | :--- |
| **00** | **Scope Validation** | Normalizes target and verifies authorization compliance. |
| **01** | **Passive OSINT** | Queries Certificate Transparency (crt.sh) & passive sources. |
| **02** | **Subdomain Discovery** | Wraps `subfinder` with native CT log fallback. |
| **03** | **DNS Intelligence** | Resolves A, AAAA, CNAME, MX, and TXT records via `dnspython`. |
| **04** | **Asset Correlation** | Correlates IPs and subdomains into structured database assets. |
| **05** | **Live Host Discovery** | Probes HTTP/HTTPS with redirect tracking, TLS, and title scraping. |
| **06** | **Service Discovery** | Safe port checks for top web/infra ports (native async socket prober + `nmap`). |
| **07** | **Tech Fingerprinting** | Analyzes headers, cookies, and DOM signatures (Wappalyzer-like). |
| **08** | **URL Intelligence** | Queries historical archive URLs (`gau` / Wayback Machine). |
| **09** | **Web Crawling** | Scope-aware crawler with depth, count, and path controls (`katana` / native). |
| **10** | **Endpoint Extraction** | Extracts URL paths, query parameters, and methods. |
| **11** | **JavaScript Intelligence**| Scans scoped `.js` files for endpoints, route strings, and masked API keys. |
| **12** | **API Reconnaissance** | Identifies OpenAPI docs, Swagger UI, and GraphQL endpoints. |
| **13** | **Content Discovery** | Safe probing for `.well-known/security.txt`, `robots.txt`, and exposed configs. |
| **14** | **Security Posture** | Safe posture checks (missing HSTS, CSP, X-Content-Type-Options, CORS). |
| **15** | **Evidence Normalization**| Deduplicates observations, hashes evidence, and persists findings. |
| **16** | **AI Analysis** | Advisory analysis of attack surface and remediation guidance. |
| **17** | **Final Reports** | Automatically exports assessment reports in HTML, Markdown, JSON, and CSV. |

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.11 or higher
- Git

### 1. Clone & Setup Virtual Environment
```bash
# Clone the repository
git clone https://github.com/shadow-reaper69/devixon.git
cd devixon

# Create and activate virtual environment
# On Linux/macOS:
python3 -m venv .venv
source .venv/bin/activate

# On Windows (PowerShell):
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install DEVIXON
```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

### 3. Verify Installation
```bash
devixon doctor
devixon self-test
```

---

## 🚀 Step-by-Step Usage Guide

### Step 1: Run Diagnostics
Run `devixon doctor` to verify your environment, database, and tool status:
```bash
devixon doctor
```

### Step 2: Define an Authorized Scope
DEVIXON strictly blocks scans unless scope is explicitly authorized:
```bash
devixon scope create \
  --domain example.com \
  --name client_scope \
  --allowed-domains "*.example.com,partner.org" \
  --allowed-ips "192.168.1.0/24" \
  --exclude "admin.example.com" \
  --exclude-paths "/logout,/admin/delete" \
  --authorized
```

Inspect the configured scope profile:
```bash
devixon scope show client_scope
```

Test if a target host or URL is permitted by scope:
```bash
devixon scope validate api.example.com --name client_scope
```

### Step 3: Execute Reconnaissance
Choose a pipeline preset:

```bash
# 1. Passive only (Zero packets sent to target infrastructure)
devixon recon passive --target example.com --scope client_scope

# 2. Quick reconnaissance (Safe HTTP & DNS checks)
devixon recon quick --target example.com --scope client_scope

# 3. Full assessment (Crawling, JS analysis, API recon, security posture)
devixon recon full --target example.com --scope client_scope
```

Check real-time pipeline status:
```bash
devixon recon status
```

### Step 4: Review Discovered Assets & Endpoints
```bash
# View correlated assets (Domains, Subdomains, IPs)
devixon assets list

# Inspect a specific asset (open ports, services, linked findings)
devixon assets inspect api.example.com

# Export asset inventory
devixon assets export --out assets.json

# View discovered endpoints & parameters
devixon endpoints list
devixon endpoints export --out endpoints.csv
```

### Step 5: Review & Validate Findings
```bash
# List all findings with severity badges
devixon findings list

# Filter by severity
devixon findings list --severity HIGH

# Inspect finding details, raw evidence, and manual verification steps
devixon findings inspect <FINDING_ID>

# Verify a finding following manual confirmation
devixon findings verify <FINDING_ID> --status CONFIRMED

# Dismiss false positives
devixon findings dismiss <FINDING_ID> --reason FALSE_POSITIVE --notes "WAF test artifact"
```

### Step 6: AI-Assisted Analysis (Optional)
If you configure an OpenAI-compatible API key or local LLM:
```bash
# Set your API key
export DEVIXON_AI_API_KEY="your-api-key"

# Analyze evidence
devixon ai analyze <FINDING_ID>

# High-level attack surface summary
devixon ai summarize
```
*(If AI is disabled or keys are absent, DEVIXON operates 100% offline without errors).*

### Step 7: Export Reports
```bash
devixon report generate --format all
devixon report list
```
Generated reports are stored in `~/devixon_reports/`:
- `*.html` — Interactive executive & technical dashboard.
- `*.md` — Formatted for Bugcrowd / HackerOne / VAPT submission.
- `*.json` — Machine-readable artifact.
- `*.csv` — Spreadsheet for remediation tracking.

---

## 🛠 Complete CLI Reference

```
devixon [COMMAND]

COMMANDS:
  doctor              Run system, database, and tool diagnostics.
  setup               Interactive onboarding setup wizard.
  self-test           Run internal regression test suite.

  config show         Display current configuration.
  config validate     Validate configuration schema and rate limits.

  target add          Register an authorized target asset.
  target list         List all registered targets.
  target inspect      Inspect registered target details.

  scope create        Create an authorized scope profile.
  scope show          Display scope profile details.
  scope validate      Validate whether a host/path is in-scope.

  recon passive       Execute passive OSINT discovery only.
  recon quick         Execute quick reconnaissance and safe posture checks.
  recon full          Execute complete 18-stage assessment pipeline.
  recon status        Check pipeline execution status and stage timings.
  recon resume        Resume an interrupted assessment session.
  recon cancel        Cancel an active assessment session.

  assets list         List discovered domains, subdomains, and IPs.
  assets inspect      Inspect host services and associated findings.
  assets export       Export assets inventory to JSON or CSV.

  endpoints list      List discovered paths, parameters, and methods.
  endpoints inspect   Inspect endpoint parameters and content types.
  endpoints export    Export endpoints inventory to JSON or CSV.

  findings list       List security findings with severity and status.
  findings inspect    Inspect evidence, impact, and verification steps.
  findings update     Update finding severity or status.
  findings verify     Confirm manual verification of a finding.
  findings dismiss    Mark finding as false positive or accepted risk.

  ai analyze          Analyze finding evidence with AI analyst.
  ai summarize        Generate attack surface risk summary.
  ai explain          Explain root cause and concepts behind a finding.
  ai remediate        Generate developer-friendly code remediation.

  report generate     Generate reports in HTML, Markdown, JSON, and CSV.
  report list         List previously generated assessment reports.
  report export       Export report to external path.

  tools check         Check external tool installation status.
  tools install-guide Display installation commands for Kali/Windows.

  database backup     Backup SQLite database safely.
  database restore    Restore database from backup file.
```

---

## 🔍 Finding Validation & Manual Checklists

DEVIXON strictly enforces that **AI or automated scanners cannot artificially promote findings to `CONFIRMED`**. Confirmation requires deterministic evidence or manual verification.

Built-in verification checklists are available in CLI (`devixon findings inspect <ID>`) for:
- **Cross-Site Scripting (XSS)**
- **SQL Injection (SQLi)**
- **Server-Side Request Forgery (SSRF)**
- **Insecure Direct Object Reference (IDOR)**
- **Authentication & Authorization Flaws**
- **Security Misconfigurations**

---

## 🧪 Running Tests

DEVIXON includes a comprehensive test suite covering scope logic, CIDR matching, target sanitization, database transactions, CVSS calculations, and report rendering:

```bash
# Run pytest test suite
pytest -v

# Run internal self-test
devixon self-test
```

---

## ⚖ Ethics & Legal Protocol

> **IMPORTANT**: DEVIXON is designed exclusively for authorized penetration testing, security research, bug bounty programs, and auditing owned infrastructure.
>
> 1. Never assess any target without explicit, documented authorization.
> 2. All automated checks must be non-destructive posture analyses.
> 3. Automated exploitation, credential spraying, and denial-of-service tests are strictly prohibited.
> 4. Adhere to your engagement's defined rules of engagement and scope limits.
