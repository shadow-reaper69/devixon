# DEVIXON — SECURITY ARCHITECTURE & SAFETY BOUNDARIES

## Strict Security Standards
1. **Mandatory Authorization Gate**: No active packet or probe may be dispatched without `authorized_by_user=True` verified by the Scope Engine.
2. **Safe Subprocess Execution**: External binaries are called strictly via `asyncio.create_subprocess_exec` with explicit argument lists. Never use `shell=True`. Arguments are validated and sanitized.
3. **Sensitive Data Redaction**:
   - API tokens, passwords, bearer tokens, and session cookies discovered in crawl/JS files are masked (`[REDACTED_API_KEY]`, `sk_live_...`).
   - Discovered credentials are never reused or submitted to targets.
4. **Non-Destructive Posture Checks Only**:
   - Headers inspection (CSP, HSTS, X-Content-Type-Options, etc.)
   - Cookie flags inspection (Secure, HttpOnly, SameSite)
   - CORS validation (origin reflection checks without dangerous state mutations)
   - Safe path checks (e.g. `/robots.txt`, `/.well-known/security.txt`, `/sitemap.xml`)
5. **AI Untrusted Input Quarantine**:
   - Target HTTP responses and headers are treated as untrusted strings.
   - Guardrails prevent prompt injection from executing system commands or expanding scope.
