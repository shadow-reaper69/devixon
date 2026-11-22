"""
CVSS v3.1 Scoring Calculator and Severity Evaluator.
Deterministic calculation without hallucination.
"""

from typing import Dict, Optional, Tuple


def calculate_cvss_base(
    av: str = "N",   # Network (N), Adjacent (A), Local (L), Physical (P)
    ac: str = "L",   # Low (L), High (H)
    pr: str = "N",   # None (N), Low (L), High (H)
    ui: str = "N",   # None (N), Required (R)
    s: str = "U",    # Unchanged (U), Changed (C)
    c: str = "H",    # High (H), Low (L), None (N)
    i: str = "H",    # High (H), Low (L), None (N)
    a: str = "N",    # High (H), Low (L), None (N)
) -> Tuple[float, str, str]:
    """
    Calculates CVSS v3.1 Base Score and returns (score, severity_rating, vector_string).
    """
    # Weights based on FIRST CVSS v3.1 specification
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"H": 0.56, "L": 0.22, "N": 0.0}

    iss = 1.0 - ((1.0 - cia_weights[c]) * (1.0 - cia_weights[i]) * (1.0 - cia_weights[a]))

    pr_val = pr_weights_c[pr] if s == "C" else pr_weights_u[pr]
    exploitability = 8.22 * av_weights[av] * ac_weights[ac] * pr_val * ui_weights[ui]

    if iss <= 0:
        base_score = 0.0
    else:
        if s == "U":
            impact = 6.42 * iss
            base_score = min(10.0, impact + exploitability)
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            base_score = min(10.0, 1.08 * (impact + exploitability))

    base_score = round(base_score, 1)

    if base_score >= 9.0:
        severity = "CRITICAL"
    elif base_score >= 7.0:
        severity = "HIGH"
    elif base_score >= 4.0:
        severity = "MEDIUM"
    elif base_score >= 0.1:
        severity = "LOW"
    else:
        severity = "INFORMATIONAL"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return base_score, severity, vector
