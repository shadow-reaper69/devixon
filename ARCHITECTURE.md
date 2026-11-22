# DEVIXON — ARCHITECTURE SPECIFICATION

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
     | - CIDR/Domain Match | | - Tool Adapters    | | - CVSS Calculator  |
     | - Excluded Routes   | | - Native Fallbacks | | - Verification DB  |
     +---------------------+ +---------+----------+ +--------------------+
                                       |
                   +-------------------+-------------------+
                   |                   |                   |
        +----------v-------+ +---------v--------+ +--------v---------+
        | Database (SQLite)| | AI Engine        | | Reporting Engine |
        | - SQLAlchemy 2.0 | | - Agnostic Client| | - Jinja2 HTML    |
        | - Migrations     | | - Pydantic Output| | - Markdown / CSV |
        | - Evidence Vault | | - Redaction Guard| | - JSON Artifacts |
        +------------------+ +------------------+ +------------------+
```

## Modular Components
1. **`core.scope`**: Enforces authorized hosts, wildcards, CIDRs, IP ranges, excluded paths, and rate limits.
2. **`core.runner`**: Safe async process execution without `shell=True`, enforcing timeouts and process tree cleanup.
3. **`recon.pipeline`**: Orchestrator executing stages 00 through 17 with database transaction persistence and progress reporting.
4. **`recon.stages.*`**: Native Python implementations + external tool wrappers (Subfinder, dnsx, httpx, nmap, katana, gau, ffuf).
5. **`security.posture`**: Safe HTTP checks (Security headers, Cookie flags, CORS, Directory listing, Sensitive file exposure, TLS validation).
6. **`ai.analyst`**: Advisory intelligence analyzing evidence and attack surface patterns without hallucinating severity.
7. **`reports.generator`**: Production-ready reports across Markdown, HTML, JSON, and CSV formats.
