"""
Pytest fixtures and configuration for DEVIXON test suite.
"""

import pytest
from pathlib import Path
from devixon.core.scope import ScopeProfile
from devixon.database.session import get_engine, init_db, get_session
from devixon.database.repository import AssessmentRepository


@pytest.fixture
def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_devixon.db"
    init_db(str(db_file))
    session = get_session(str(db_file))
    yield session
    session.close()


@pytest.fixture
def sample_scope():
    return ScopeProfile(
        primary_domain="example.com",
        allowed_domains=["*.example.com", "partner.org"],
        allowed_ips=["10.0.0.0/24", "192.168.1.100"],
        excluded_targets=["admin.example.com", "10.0.0.5"],
        excluded_paths=["/logout", "/admin/delete"],
        authorized_by_user=True,
    )
