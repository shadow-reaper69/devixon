"""
Unit tests for Enhanced Reconnaissance Database Models and Repository CRUD.
"""

import pytest
from devixon.database.repository import AssessmentRepository


def test_subdomain_crud(temp_db):
    repo = AssessmentRepository(temp_db)
    ass = repo.create_assessment("target.com", '{"primary_domain":"target.com"}', "FULL")

    # Regular subdomain
    sub = repo.add_subdomain(
        assessment_id=ass.id,
        subdomain="api.target.com",
        resolved_ip="1.2.3.4",
        resolution_status="RESOLVED",
        discovery_source="SUBFINDER",
    )
    assert sub.id is not None
    assert sub.subdomain == "api.target.com"
    assert sub.resolution_status == "RESOLVED"

    # Localhost / IP target marked NOT_APPLICABLE
    local_sub = repo.add_subdomain(
        assessment_id=ass.id,
        subdomain="127.0.0.1",
        resolved_ip="127.0.0.1",
        resolution_status="NOT_APPLICABLE",
        discovery_source="TARGET_INPUT",
    )
    assert local_sub.resolution_status == "NOT_APPLICABLE"


def test_livehost_and_discovered_paths_crud(temp_db):
    repo = AssessmentRepository(temp_db)
    ass = repo.create_assessment("target.com", '{}', "FULL")

    lh = repo.add_live_host(
        assessment_id=ass.id,
        url="https://api.target.com",
        host="api.target.com",
        status_code=200,
        title="Welcome",
        web_server="nginx",
        technologies=["Server:nginx", "Framework:FastAPI"],
        response_time_ms=32.5,
    )
    assert lh.id is not None
    assert lh.status_code == 200
    assert "nginx" in lh.technologies_json

    dp = repo.add_discovered_path(
        assessment_id=ass.id,
        host="api.target.com",
        url="https://api.target.com/api/v1",
        path="/api/v1",
        status_code=200,
        content_length=512,
        discovery_tool="FFUF",
    )
    assert dp.id is not None
    assert dp.path == "/api/v1"
    assert dp.discovery_tool == "FFUF"


def test_internal_links_and_parameters_crud(temp_db):
    repo = AssessmentRepository(temp_db)
    ass = repo.create_assessment("target.com", '{}', "FULL")

    link = repo.add_internal_link(
        assessment_id=ass.id,
        source_url="https://target.com",
        destination_url="https://target.com/about",
        method="GET",
        link_type="a_href",
        is_internal=True,
        crawl_depth=1,
    )
    assert link.id is not None
    assert link.is_internal is True

    ep = repo.add_endpoint(
        assessment_id=ass.id,
        url="https://target.com/search?q=test&lang=en",
        path="/search",
        method="GET",
        params="q,lang",
    )
    assert ep.id is not None

    p1 = repo.add_parameter(
        assessment_id=ass.id,
        endpoint_id=ep.id,
        name="q",
        param_type="query",
        example_value="test",
    )
    assert p1.id is not None
    assert p1.name == "q"


def test_js_assets_and_technology_crud(temp_db):
    repo = AssessmentRepository(temp_db)
    ass = repo.create_assessment("target.com", '{}', "FULL")

    js = repo.add_js_asset(
        assessment_id=ass.id,
        url="https://target.com/bundle.js",
        host="target.com",
        endpoints_found=["/api/v1/data"],
        routes_found=["/dashboard"],
        secrets_found=[{"type": "API Key", "masked": "sk_live_****"}],
        source_map_url="https://target.com/bundle.js.map",
    )
    assert js.id is not None
    assert "bundle.js.map" in js.source_map_url

    tech = repo.add_technology(
        assessment_id=ass.id,
        host="target.com",
        name="React",
        category="Library",
        confidence="CONFIRMED",
    )
    assert tech.id is not None
    assert tech.name == "React"
