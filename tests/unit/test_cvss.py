"""
Unit tests for CVSS v3.1 calculator and severity evaluation.
"""

from devixon.security.cvss import calculate_cvss_base


def test_cvss_critical_calculation():
    # Network, Low complexity, No privs, No UI, Unchanged, High C, High I, High A
    score, sev, vector = calculate_cvss_base(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
    assert score >= 9.0
    assert sev == "CRITICAL"
    assert "AV:N" in vector


def test_cvss_medium_calculation():
    score, sev, vector = calculate_cvss_base(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="L", a="N")
    assert 4.0 <= score <= 6.9
    assert sev == "MEDIUM"


def test_cvss_zero_impact():
    score, sev, vector = calculate_cvss_base(c="N", i="N", a="N")
    assert score == 0.0
    assert sev == "INFORMATIONAL"
