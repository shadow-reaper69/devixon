"""
Finding validation engine and manual verification checklist system.
Enforces evidence rules and prevents AI hallucination or superficial scanner confirmation.
"""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ValidationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    INFORMATIONAL = "INFORMATIONAL"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VerificationChecklist(BaseModel):
    category: str
    description: str
    required_evidence: List[str]
    manual_steps: List[str]
    safe_test_guidance: str
    prohibited_actions: List[str]


VERIFICATION_CHECKLISTS: Dict[str, VerificationChecklist] = {
    "XSS": VerificationChecklist(
        category="Cross-Site Scripting (XSS)",
        description="Verify context-specific payload reflection and JavaScript execution context without triggering unintended state.",
        required_evidence=[
            "Sanitized HTTP request demonstrating input reflection",
            "HTTP response displaying unencoded payload within executable HTML/JS context",
            "Context specification (e.g. HTML body, attribute value, script block)",
        ],
        manual_steps=[
            "1. Confirm user input is reflected in response without sufficient context-aware escaping or encoding.",
            "2. Verify whether Content-Security-Policy (CSP) blocks inline execution.",
            "3. Safely test with benign proof-of-concept such as `<script>console.log(1)</script>` or harmless event handler.",
        ],
        safe_test_guidance="Never attempt session stealing, credential harvesting, or intrusive DOM modifications.",
        prohibited_actions=["Automated blind payload fuzzing against non-test users", "WAF evasion brute forcing"],
    ),
    "SQL_INJECTION": VerificationChecklist(
        category="SQL Injection",
        description="Verify database query interpretation of user input through deterministic syntax variation or safe parameter tests.",
        required_evidence=[
            "Deterministic syntax-induced behavioral change or verified database error message",
            "Proof of differential response matching query semantics",
        ],
        manual_steps=[
            "1. Test parameter with standard benign single quote / double quote to observe syntax error or response variation.",
            "2. Confirm parameterized queries are absent in server-side query construction.",
            "3. Use safe non-destructive arithmetic expressions (e.g., id=10-2 vs id=8).",
        ],
        safe_test_guidance="Never extract databases, drop tables, execute xp_cmdshell, or perform sleep-based denial of service.",
        prohibited_actions=["Unbounded sleep/benchmark payloads", "Mass database dumping", "ALTER/DROP/UPDATE queries"],
    ),
    "SSRF": VerificationChecklist(
        category="Server-Side Request Forgery (SSRF)",
        description="Verify server-initiated HTTP/network requests to arbitrary internal or external destinations.",
        required_evidence=[
            "Confirmed server interaction with controlled Burp Collaborator or Canary host",
            "Evidence that loopback (127.0.0.1) or cloud metadata endpoints (169.254.169.254) are reachable by server",
        ],
        manual_steps=[
            "1. Identify parameter accepting URL or IP destination.",
            "2. Supply an out-of-band listener (e.g., Burp Collaborator or authorized canary).",
            "3. Verify origin IP of the DNS or HTTP request matches the target server cluster.",
        ],
        safe_test_guidance="Never pivot to scan internal enterprise subnets or retrieve internal cloud credentials.",
        prohibited_actions=["Cloud metadata credential extraction", "Internal port scanning / lateral movement"],
    ),
    "IDOR": VerificationChecklist(
        category="Insecure Direct Object Reference / Broken Access Control",
        description="Verify unauthorized horizontal or vertical access to resource identifiers.",
        required_evidence=[
            "HTTP response showing data of User B accessed using User A's active session",
            "Proof of missing server-side authorization check",
        ],
        manual_steps=[
            "1. Authenticate as Test User A and record resource ID.",
            "2. Authenticate as Test User B.",
            "3. Request User A's resource ID using User B's session token.",
            "4. Verify whether User A's private data is returned or state was modified.",
        ],
        safe_test_guidance="Perform tests strictly between two dedicated accounts created by the authorized tester.",
        prohibited_actions=["Accessing real production user records", "Modifying non-test account data"],
    ),
    "AUTH_FLAWS": VerificationChecklist(
        category="Authentication Flaws",
        description="Verify bypass of authentication mechanisms, password reset logic, or token validation.",
        required_evidence=[
            "Detailed trace of token omission or tampering accepted by backend",
            "Proof of session fixation or unverified signature acceptance",
        ],
        manual_steps=[
            "1. Inspect JWT / session token structure and validation algorithm (e.g. 'none' algorithm or missing signature verification).",
            "2. Check password reset flow for predictable tokens or host header poisoning.",
            "3. Verify rate limiting on login endpoints without locking real user accounts.",
        ],
        safe_test_guidance="Test only on designated test accounts.",
        prohibited_actions=["Credential stuffing", "Account lockout DoS", "Brute-forcing production users"],
    ),
    "MISCONFIGURATION": VerificationChecklist(
        category="Security Misconfiguration",
        description="Verify exposed debug endpoints, default credentials, or missing critical security headers.",
        required_evidence=[
            "HTTP response headers or exposed interface screenshot/text",
            "Direct URL accessibility without required authorization",
        ],
        manual_steps=[
            "1. Verify if endpoint (e.g. /actuator, /.git, /phpinfo.php, /swagger-ui.html) is publicly reachable without authentication.",
            "2. Check if sensitive internal information or credentials are displayed.",
            "3. Verify impact on confidentiality or system integrity.",
        ],
        safe_test_guidance="Do not download entire git repositories or production databases.",
        prohibited_actions=["Mass scraping of customer data", "Modifying administrative configurations"],
    ),
}


def get_verification_checklist(category: str) -> Optional[VerificationChecklist]:
    normalized = category.upper().replace(" ", "_").replace("-", "_")
    for key, cl in VERIFICATION_CHECKLISTS.items():
        if key in normalized or normalized in key:
            return cl
    return VERIFICATION_CHECKLISTS.get("MISCONFIGURATION")


def evaluate_evidence_confidence(
    category: str,
    evidence_types: List[str],
    has_manual_verification: bool = False,
    is_automated_scanner_only: bool = True,
) -> Tuple[ValidationStatus, str]:
    """
    Evaluates evidence against strict rules to prevent artificial promotion to CONFIRMED.
    """
    if has_manual_verification:
        return ValidationStatus.CONFIRMED, "Finding was manually reproduced and verified by tester."

    # If it is only based on scanner assertion or version banner
    if "VERSION_BANNER" in evidence_types and len(evidence_types) == 1:
        return ValidationStatus.INFORMATIONAL, "Finding based solely on banner version without proof of exploitability."

    if "SECURITY_HEADER" in evidence_types:
        # Missing headers are deterministic but informational / low
        return ValidationStatus.CONFIRMED, "Deterministic observation of missing or misconfigured HTTP security header."

    if "PUBLIC_EXPOSURE" in evidence_types:
        return ValidationStatus.LIKELY, "Endpoint is publicly accessible; requires tester review to assess confidentiality impact."

    if is_automated_scanner_only:
        return ValidationStatus.NEEDS_REVIEW, "Automated heuristic detection requires manual verification."

    return ValidationStatus.NEEDS_REVIEW, "Requires review."
