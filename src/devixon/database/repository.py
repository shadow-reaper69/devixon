"""
Database repository functions for DEVIXON.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json
from sqlalchemy.orm import Session
from devixon.database.models import (
    Assessment,
    Asset,
    Service,
    Endpoint,
    Finding,
    Evidence,
    ScanStage,
)


class AssessmentRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_assessment(
        self,
        target: str,
        scope_profile_json: str,
        scan_profile: str = "QUICK",
    ) -> Assessment:
        assessment = Assessment(
            target=target,
            scope_profile_json=scope_profile_json,
            scan_profile=scan_profile,
            status="PENDING",
            start_time=datetime.now(timezone.utc),
        )
        self.session.add(assessment)
        self.session.commit()
        self.session.refresh(assessment)
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[Assessment]:
        return self.session.query(Assessment).filter(Assessment.id == assessment_id).first()

    def get_latest_assessment(self) -> Optional[Assessment]:
        return self.session.query(Assessment).order_by(Assessment.created_at.desc()).first()

    def list_assessments(self, limit: int = 50) -> List[Assessment]:
        return self.session.query(Assessment).order_by(Assessment.created_at.desc()).limit(limit).all()

    def update_status(self, assessment_id: str, status: str, summary: Optional[Dict[str, Any]] = None):
        assessment = self.get_assessment(assessment_id)
        if assessment:
            assessment.status = status
            if status in ("COMPLETED", "FAILED", "CANCELLED"):
                assessment.end_time = datetime.now(timezone.utc)
            if summary:
                assessment.summary_json = json.dumps(summary)
            self.session.commit()

    def add_asset(
        self,
        assessment_id: str,
        hostname: str,
        ip_address: Optional[str] = None,
        asset_type: str = "SUBDOMAIN",
        scope_status: str = "IN_SCOPE",
        discovery_source: str = "PASSIVE",
        tags: Optional[List[str]] = None,
    ) -> Asset:
        existing = (
            self.session.query(Asset)
            .filter(Asset.assessment_id == assessment_id, Asset.hostname == hostname)
            .first()
        )
        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            if ip_address and not existing.ip_address:
                existing.ip_address = ip_address
            self.session.commit()
            return existing

        asset = Asset(
            assessment_id=assessment_id,
            hostname=hostname,
            ip_address=ip_address,
            asset_type=asset_type,
            scope_status=scope_status,
            discovery_source=discovery_source,
            tags=",".join(tags) if tags else "",
        )
        self.session.add(asset)
        self.session.commit()
        self.session.refresh(asset)
        return asset

    def add_service(
        self,
        asset_id: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "unknown",
        version: Optional[str] = None,
        banner: Optional[str] = None,
        confidence: str = "CONFIRMED",
    ) -> Service:
        existing = (
            self.session.query(Service)
            .filter(Service.asset_id == asset_id, Service.port == port, Service.protocol == protocol)
            .first()
        )
        if existing:
            existing.service_name = service_name
            existing.version = version
            existing.banner = banner
            self.session.commit()
            return existing

        service = Service(
            asset_id=asset_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            version=version,
            banner=banner,
            confidence=confidence,
        )
        self.session.add(service)
        self.session.commit()
        self.session.refresh(service)
        return service

    def add_endpoint(
        self,
        asset_id: str,
        url: str,
        path: str,
        method: str = "GET",
        params: Optional[str] = None,
        content_type: Optional[str] = None,
        status_code: Optional[int] = None,
        discovery_source: str = "CRAWLER",
    ) -> Endpoint:
        existing = (
            self.session.query(Endpoint)
            .filter(Endpoint.asset_id == asset_id, Endpoint.url == url, Endpoint.method == method)
            .first()
        )
        if existing:
            if status_code:
                existing.status_code = status_code
            self.session.commit()
            return existing

        ep = Endpoint(
            asset_id=asset_id,
            url=url,
            path=path,
            method=method,
            params=params,
            content_type=content_type,
            status_code=status_code,
            discovery_source=discovery_source,
        )
        self.session.add(ep)
        self.session.commit()
        self.session.refresh(ep)
        return ep

    def add_finding(
        self,
        assessment_id: str,
        title: str,
        category: str,
        severity: str,
        description: str,
        impact: str,
        reproduction_steps: str,
        remediation: str,
        asset_id: Optional[str] = None,
        endpoint_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        cvss_vector: Optional[str] = None,
        confidence: str = "LIKELY",
        verification_status: str = "NEEDS_REVIEW",
        references: Optional[str] = None,
    ) -> Finding:
        finding = Finding(
            assessment_id=assessment_id,
            asset_id=asset_id,
            endpoint_id=endpoint_id,
            title=title,
            category=category,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            confidence=confidence,
            verification_status=verification_status,
            description=description,
            impact=impact,
            reproduction_steps=reproduction_steps,
            remediation=remediation,
            references=references,
        )
        self.session.add(finding)
        self.session.commit()
        self.session.refresh(finding)
        return finding

    def add_evidence(
        self,
        finding_id: str,
        evidence_type: str,
        description: str,
        sanitized_data: str,
        source: str = "SCANNER",
        data_hash: Optional[str] = None,
    ) -> Evidence:
        evidence = Evidence(
            finding_id=finding_id,
            evidence_type=evidence_type,
            description=description,
            sanitized_data=sanitized_data,
            source=source,
            data_hash=data_hash,
        )
        self.session.add(evidence)
        self.session.commit()
        self.session.refresh(evidence)
        return evidence
