"""
Unit tests for Database Models and Repository transactions.
"""

from devixon.database.repository import AssessmentRepository


def test_assessment_crud(temp_db):
    repo = AssessmentRepository(temp_db)
    ass = repo.create_assessment("test.local", '{"name":"test"}', "QUICK")
    assert ass.id is not None
    assert ass.target == "test.local"
    assert ass.status == "PENDING"

    repo.update_status(ass.id, "COMPLETED")
    updated = repo.get_assessment(ass.id)
    assert updated.status == "COMPLETED"


def test_asset_and_finding_relationships(temp_db):
    repo = AssessmentRepository(temp_db)
    ass = repo.create_assessment("test.local", '{}', "QUICK")

    asset = repo.add_asset(ass.id, "sub.test.local", "1.2.3.4")
    assert asset.hostname == "sub.test.local"

    finding = repo.add_finding(
        assessment_id=ass.id,
        title="Missing CSP",
        category="Security Misconfiguration",
        severity="MEDIUM",
        description="CSP missing",
        impact="Low",
        reproduction_steps="Curl response",
        remediation="Add header",
        asset_id=asset.id,
    )
    assert finding.id is not None
    assert finding.asset_id == asset.id

    ev = repo.add_evidence(
        finding_id=finding.id,
        evidence_type="HTTP_HEADER",
        description="Header trace",
        sanitized_data="Content-Security-Policy: null",
    )
    assert ev.id is not None
    assert ev.finding_id == finding.id
