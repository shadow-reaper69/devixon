"""
SQLAlchemy 2.0 ORM models for DEVIXON framework.
Enhanced with dedicated models for Subdomains, DNS Records, Live Hosts, Discovered Paths,
Internal Links, Parameters, JavaScript Assets, Technologies, and Scan Stages.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from devixon.database.session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target = Column(String(255), nullable=False)
    scope_profile_json = Column(Text, nullable=False)
    scan_profile = Column(String(50), nullable=False, default="QUICK")  # PASSIVE, QUICK, FULL, SUBDOMAINS, HOSTS, CRAWL, PATHS, URLS, ENDPOINTS
    status = Column(String(50), nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, CANCELLED, FAILED
    start_time = Column(DateTime, default=utc_now)
    end_time = Column(DateTime, nullable=True)
    summary_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    # Relationships
    assets = relationship("Asset", back_populates="assessment", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="assessment", cascade="all, delete-orphan")
    dns_records = relationship("DNSRecord", back_populates="assessment", cascade="all, delete-orphan")
    live_hosts = relationship("LiveHost", back_populates="assessment", cascade="all, delete-orphan")
    discovered_paths = relationship("DiscoveredPath", back_populates="assessment", cascade="all, delete-orphan")
    internal_links = relationship("InternalLink", back_populates="assessment", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="assessment", cascade="all, delete-orphan")
    parameters = relationship("Parameter", back_populates="assessment", cascade="all, delete-orphan")
    js_assets = relationship("JavaScriptAsset", back_populates="assessment", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="assessment", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="assessment", cascade="all, delete-orphan")
    stages = relationship("ScanStage", back_populates="assessment", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    asset_type = Column(String(50), default="SUBDOMAIN")  # DOMAIN, SUBDOMAIN, IP
    scope_status = Column(String(50), default="IN_SCOPE")  # IN_SCOPE, OUT_OF_SCOPE, EXCLUDED
    discovery_source = Column(String(100), default="PASSIVE")
    tags = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="assets")
    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_asset_hostname", "hostname"),
        Index("idx_asset_assessment", "assessment_id"),
    )


class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    subdomain = Column(String(255), nullable=False)
    resolved_ip = Column(String(45), nullable=True)
    resolution_status = Column(String(50), default="RESOLVED")  # RESOLVED, UNRESOLVED, NOT_APPLICABLE
    discovery_source = Column(String(100), default="SUBFINDER")
    dns_records_json = Column(Text, nullable=True)  # JSON serialized map of records
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="subdomains")

    __table_args__ = (
        Index("idx_subdomain_assessment", "assessment_id"),
        Index("idx_subdomain_name", "subdomain"),
    )


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    host = Column(String(255), nullable=False)
    record_type = Column(String(20), nullable=False)  # A, AAAA, CNAME, MX, TXT, NS, PTR
    value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="dns_records")

    __table_args__ = (
        Index("idx_dns_record_host", "host"),
        Index("idx_dns_record_assessment", "assessment_id"),
    )


class LiveHost(Base):
    __tablename__ = "live_hosts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    host = Column(String(255), nullable=False)
    status_code = Column(Integer, nullable=False)
    title = Column(String(255), nullable=True)
    web_server = Column(String(100), nullable=True)
    technologies_json = Column(Text, nullable=True)
    content_type = Column(String(100), nullable=True)
    response_time_ms = Column(Float, nullable=True)
    redirect_destination = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="live_hosts")

    __table_args__ = (
        Index("idx_livehost_assessment", "assessment_id"),
        Index("idx_livehost_host", "host"),
    )


class DiscoveredPath(Base):
    __tablename__ = "discovered_paths"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    host = Column(String(255), nullable=False)
    url = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=False)
    content_length = Column(Integer, default=0)
    redirect_location = Column(Text, nullable=True)
    response_time_ms = Column(Float, nullable=True)
    method = Column(String(10), default="GET")
    discovery_tool = Column(String(50), default="FFUF")
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="discovered_paths")

    __table_args__ = (
        Index("idx_path_assessment", "assessment_id"),
        Index("idx_path_host", "host"),
    )


class InternalLink(Base):
    __tablename__ = "internal_links"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    source_url = Column(Text, nullable=False)
    destination_url = Column(Text, nullable=False)
    method = Column(String(10), default="GET")
    link_type = Column(String(50), default="a_href")  # a_href, form_action, script_src, link_href, api_fetch
    is_internal = Column(Boolean, default=True)
    status_code = Column(Integer, nullable=True)
    crawl_depth = Column(Integer, default=1)
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="internal_links")

    __table_args__ = (
        Index("idx_link_assessment", "assessment_id"),
    )


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    url = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    method = Column(String(10), default="GET")
    params = Column(Text, nullable=True)
    content_type = Column(String(100), nullable=True)
    status_code = Column(Integer, nullable=True)
    is_historical = Column(Boolean, default=False)  # True if discovered solely from archive/GAU
    discovery_source = Column(String(100), default="CRAWLER")  # KATANA, GAU, CRAWLER, JS

    assessment = relationship("Assessment", back_populates="endpoints")
    asset = relationship("Asset", back_populates="endpoints")
    parameters = relationship("Parameter", back_populates="endpoint", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="endpoint", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_endpoint_assessment", "assessment_id"),
        Index("idx_endpoint_asset", "asset_id"),
    )


class Parameter(Base):
    __tablename__ = "parameters"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    endpoint_id = Column(String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(100), nullable=False)
    param_type = Column(String(50), default="query")  # query, body, path, header
    example_value = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="parameters")
    endpoint = relationship("Endpoint", back_populates="parameters")

    __table_args__ = (
        Index("idx_param_endpoint", "endpoint_id"),
        Index("idx_param_assessment", "assessment_id"),
    )


class JavaScriptAsset(Base):
    __tablename__ = "javascript_assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    host = Column(String(255), nullable=False)
    endpoints_found_json = Column(Text, nullable=True)
    routes_found_json = Column(Text, nullable=True)
    secrets_found_json = Column(Text, nullable=True)  # Strictly sanitized / masked
    source_map_url = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="js_assets")

    __table_args__ = (
        Index("idx_js_assessment", "assessment_id"),
        Index("idx_js_host", "host"),
    )


class Technology(Base):
    __tablename__ = "technologies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    host = Column(String(255), nullable=False)
    name = Column(String(100), nullable=False)
    category = Column(String(100), default="Web Server")  # Web Server, Framework, CMS, Library, CDN, Reverse Proxy
    version = Column(String(100), nullable=True)
    confidence = Column(String(50), default="CONFIRMED")
    detection_source = Column(String(100), default="HTTP_HEADER")
    first_seen = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="technologies")

    __table_args__ = (
        Index("idx_tech_assessment", "assessment_id"),
        Index("idx_tech_host", "host"),
    )


class Service(Base):
    __tablename__ = "services"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(20), default="tcp")
    service_name = Column(String(100), default="unknown")
    version = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)
    confidence = Column(String(50), default="CONFIRMED")

    asset = relationship("Asset", back_populates="services")

    __table_args__ = (
        Index("idx_service_asset_port", "asset_id", "port"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    endpoint_id = Column(String(36), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    confidence = Column(String(50), default="LIKELY")
    verification_status = Column(String(50), default="NEEDS_REVIEW")
    description = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    reproduction_steps = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    references = Column(Text, nullable=True)
    false_positive_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now)

    assessment = relationship("Assessment", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    endpoint = relationship("Endpoint", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_finding_assessment", "assessment_id"),
        Index("idx_finding_severity", "severity"),
        Index("idx_finding_status", "verification_status"),
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    sanitized_data = Column(Text, nullable=False)
    source = Column(String(100), default="SCANNER")
    data_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now)

    finding = relationship("Finding", back_populates="evidence")


class ScanStage(Base):
    __tablename__ = "scan_stages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False)
    stage_id = Column(String(50), nullable=False)
    name = Column(String(100), nullable=False)
    status = Column(String(50), default="PENDING")
    progress = Column(Float, default=0.0)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    duration = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0)

    assessment = relationship("Assessment", back_populates="stages")

    __table_args__ = (
        Index("idx_stage_assessment", "assessment_id"),
    )
