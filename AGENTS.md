# DEVIXON AGENTS & DEVELOPMENT PROTOCOLS

## Operational Principles
1. **Safety First**: No active network probes against any target without confirmed scope authorization.
2. **Defensive & Non-Destructive**: All automated checks must be non-destructive posture analyses. Never perform automated exploitation, password spraying, or denial of service.
3. **Evidence Over Speculation**: Every finding must link to concrete sanitized evidence (headers, status codes, sanitized responses).
4. **Graceful Degradation**: External binaries (Subfinder, Katana, Nmap, ffuf, etc.) are optional adapters. Native Python implementations provide fully operational fallback capabilities.
5. **AI Independence**: AI is advisory and structured via Pydantic; core recon, analysis, database persistence, and report generation run completely offline without AI keys.
