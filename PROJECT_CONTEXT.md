# DEVIXON — PROJECT CONTEXT

## Identity
- **Name**: DEVIXON
- **Tagline**: AI-Assisted Reconnaissance & Vulnerability Intelligence
- **Platform**: Terminal-first, Python 3.11+, cross-platform (Linux/Kali, Windows, macOS)
- **Primary Interface**: CLI built with Typer & Rich

## Production Implementation Status
- **CLI Commands**:
  - `devixon doctor` — Full diagnostic report on Python, OS, DB, and external tools
  - `devixon setup` — Interactive configuration wizard
  - `devixon self-test` — Automated internal test suite
  - `devixon scope create|show|validate` — Scope profile definition and enforcement
  - `devixon recon passive|quick|full` — Asynchronous multi-stage recon pipeline
  - `devixon assets list` — Discovered domains, subdomains, IPs, and tags
  - `devixon endpoints list` — Discovered URLs, paths, and query parameters
  - `devixon findings list|inspect|verify` — Evidence-backed findings with manual checklists
  - `devixon report generate` — Exports to HTML (dark mode), Markdown, JSON, and CSV
  - `devixon ai analyze` — Advisory AI assessment with safe offline fallback
