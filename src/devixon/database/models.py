"""
SQLAlchemy 2.0 ORM models for DEVIXON framework.
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
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
    scan_profile = Column(String(50), nullable=False, default="QUICK")  # PASSIVE, QUICK, FULL, CUSTOM
    status = Column(String(50), nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, CANCELLED, FAILED
    start_time = Column(DateTime, default=utc_now)
    end_time = Column(DateTime, nullable=True)
    summary_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    # Relationships
    assets = relationship("Asset", back_populates="assessment", cascade="all, delete-orphan")
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
    tags = Column(Text, nullable=True)  # JSON or comma-separated
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


class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    method = Column(String(10), default="GET")
    params = Column(Text, nullable=True)
    content_type = Column(String(100), nullable=True)
    status_code = Column(Integer, nullable=True)
    discovery_source = Column(String(100), default="CRAWLER")

    asset = relationship("Asset", back_populates="endpoints")
    findings = relationship("Finding", back_populates="endpoint", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_endpoint_asset", "asset_id"),
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
    confidence = Column(String(50), default="LIKELY")  # CONFIRMED, LIKELY, SUSPECTED, INFORMATIONAL
    verification_status = Column(String(50), default="NEEDS_REVIEW")  # CONFIRMED, LIKELY, NEEDS_REVIEW, INFORMATIONAL, FALSE_POSITIVE, FIXED
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
    evidence_type = Column(String(100), nullable=False)  # HTTP_HEADER, RESPONSE_BODY, TLS_CERT, etc.
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
    status = Column(String(50), default="PENDING")  # PENDING, RUNNING, COMPLETED, SKIPPED, FAILED, CANCELLED
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
