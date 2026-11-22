# DEVIXON — TEST PLAN

## Test Pyramid
1. **Unit Tests (`tests/unit/`)**:
   - Scope engine evaluation (wildcards, exact domains, IP ranges, excluded paths)
   - Target normalization (`https://foo.com/` -> `foo.com`, etc.)
   - DNS record parsing and error handling
   - HTTP header and security posture evaluation
   - Database model transactions and CRUD
   - Report generator template rendering
2. **Integration Tests (`tests/integration/`)**:
   - Pipeline stage lifecycle (pending -> running -> completed)
   - Graceful skip when external tools are missing
   - Safe subprocess timeout enforcement
   - AI provider error fallbacks
3. **Security Boundary Tests (`tests/security/`)**:
   - Attempting to scan out-of-scope targets (must raise `ScopeViolationError`)
   - Argument injection prevention in subprocess runners
   - Redaction of sensitive secrets in evidence storage
