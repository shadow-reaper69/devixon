"""
Database repository functions for DEVIXON.
Includes CRUD operations for Assessments, Assets, Subdomains, DNSRecords,
LiveHosts, DiscoveredPaths, InternalLinks, Endpoints, Parameters, JavaScriptAssets, Technologies,
Findings, and Evidence.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import json
from sqlalchemy.orm import Session
from devixon.database.models import (
    Assessment,
    Asset,
    Subdomain,
    DNSRecord,
    LiveHost,
    DiscoveredPath,
    InternalLink,
    Endpoint,
    Parameter,
    JavaScriptAsset,
    Technology,
    Service,
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

    def add_subdomain(
        self,
        assessment_id: str,
        subdomain: str,
        resolved_ip: Optional[str] = None,
        resolution_status: str = "RESOLVED",
        discovery_source: str = "SUBFINDER",
        dns_records: Optional[Dict[str, Any]] = None,
    ) -> Subdomain:
        existing = (
            self.session.query(Subdomain)
            .filter(Subdomain.assessment_id == assessment_id, Subdomain.subdomain == subdomain)
            .first()
        )
        records_json = json.dumps(dns_records) if dns_records else None
        if existing:
            if resolved_ip and not existing.resolved_ip:
                existing.resolved_ip = resolved_ip
            if records_json:
                existing.dns_records_json = records_json
            existing.resolution_status = resolution_status
            self.session.commit()
            return existing

        sub = Subdomain(
            assessment_id=assessment_id,
            subdomain=subdomain,
            resolved_ip=resolved_ip,
            resolution_status=resolution_status,
            discovery_source=discovery_source,
            dns_records_json=records_json,
        )
        self.session.add(sub)
        self.session.commit()
        self.session.refresh(sub)
        return sub

    def add_dns_record(
        self,
        assessment_id: str,
        host: str,
        record_type: str,
        value: str,
        ttl: Optional[int] = None,
    ) -> DNSRecord:
        existing = (
            self.session.query(DNSRecord)
            .filter(
                DNSRecord.assessment_id == assessment_id,
                DNSRecord.host == host,
                DNSRecord.record_type == record_type,
                DNSRecord.value == value,
            )
            .first()
        )
        if existing:
            return existing

        rec = DNSRecord(
            assessment_id=assessment_id,
            host=host,
            record_type=record_type,
            value=value,
            ttl=ttl,
        )
        self.session.add(rec)
        self.session.commit()
        self.session.refresh(rec)
        return rec

    def add_live_host(
        self,
        assessment_id: str,
        url: str,
        host: str,
        status_code: int,
        title: Optional[str] = None,
        web_server: Optional[str] = None,
        technologies: Optional[List[str]] = None,
        content_type: Optional[str] = None,
        response_time_ms: Optional[float] = None,
        redirect_destination: Optional[str] = None,
    ) -> LiveHost:
        existing = (
            self.session.query(LiveHost)
            .filter(LiveHost.assessment_id == assessment_id, LiveHost.url == url)
            .first()
        )
        tech_json = json.dumps(technologies) if technologies else None
        if existing:
            existing.status_code = status_code
            existing.title = title or existing.title
            existing.web_server = web_server or existing.web_server
            existing.technologies_json = tech_json or existing.technologies_json
            existing.content_type = content_type or existing.content_type
            existing.response_time_ms = response_time_ms or existing.response_time_ms
            existing.redirect_destination = redirect_destination or existing.redirect_destination
            self.session.commit()
            return existing

        lh = LiveHost(
            assessment_id=assessment_id,
            url=url,
            host=host,
            status_code=status_code,
            title=title,
            web_server=web_server,
            technologies_json=tech_json,
            content_type=content_type,
            response_time_ms=response_time_ms,
            redirect_destination=redirect_destination,
        )
        self.session.add(lh)
        self.session.commit()
        self.session.refresh(lh)
        return lh

    def add_discovered_path(
        self,
        assessment_id: str,
        host: str,
        url: str,
        path: str,
        status_code: int,
        content_length: int = 0,
        redirect_location: Optional[str] = None,
        response_time_ms: Optional[float] = None,
        method: str = "GET",
        discovery_tool: str = "FFUF",
    ) -> DiscoveredPath:
        existing = (
            self.session.query(DiscoveredPath)
            .filter(
                DiscoveredPath.assessment_id == assessment_id,
                DiscoveredPath.url == url,
                DiscoveredPath.method == method,
            )
            .first()
        )
        if existing:
            existing.status_code = status_code
            existing.content_length = content_length
            existing.redirect_location = redirect_location
            self.session.commit()
            return existing

        dp = DiscoveredPath(
            assessment_id=assessment_id,
            host=host,
            url=url,
            path=path,
            status_code=status_code,
            content_length=content_length,
            redirect_location=redirect_location,
            response_time_ms=response_time_ms,
            method=method,
            discovery_tool=discovery_tool,
        )
        self.session.add(dp)
        self.session.commit()
        self.session.refresh(dp)
        return dp

    def add_internal_link(
        self,
        assessment_id: str,
        source_url: str,
        destination_url: str,
        method: str = "GET",
        link_type: str = "a_href",
        is_internal: bool = True,
        status_code: Optional[int] = None,
        crawl_depth: int = 1,
    ) -> InternalLink:
        existing = (
            self.session.query(InternalLink)
            .filter(
                InternalLink.assessment_id == assessment_id,
                InternalLink.source_url == source_url,
                InternalLink.destination_url == destination_url,
            )
            .first()
        )
        if existing:
            return existing

        link = InternalLink(
            assessment_id=assessment_id,
            source_url=source_url,
            destination_url=destination_url,
            method=method,
            link_type=link_type,
            is_internal=is_internal,
            status_code=status_code,
            crawl_depth=crawl_depth,
        )
        self.session.add(link)
        self.session.commit()
        self.session.refresh(link)
        return link

    def add_endpoint(
        self,
        assessment_id: str,
        url: str,
        path: str,
        method: str = "GET",
        params: Optional[str] = None,
        content_type: Optional[str] = None,
        status_code: Optional[int] = None,
        is_historical: bool = False,
        discovery_source: str = "CRAWLER",
        asset_id: Optional[str] = None,
    ) -> Endpoint:
        existing = (
            self.session.query(Endpoint)
            .filter(
                Endpoint.assessment_id == assessment_id,
                Endpoint.url == url,
                Endpoint.method == method,
            )
            .first()
        )
        if existing:
            if status_code:
                existing.status_code = status_code
            if params and not existing.params:
                existing.params = params
            self.session.commit()
            return existing

        ep = Endpoint(
            assessment_id=assessment_id,
            asset_id=asset_id,
            url=url,
            path=path,
            method=method,
            params=params,
            content_type=content_type,
            status_code=status_code,
            is_historical=is_historical,
            discovery_source=discovery_source,
        )
        self.session.add(ep)
        self.session.commit()
        self.session.refresh(ep)
        return ep

    def add_parameter(
        self,
        assessment_id: str,
        endpoint_id: str,
        name: str,
        param_type: str = "query",
        example_value: Optional[str] = None,
    ) -> Parameter:
        existing = (
            self.session.query(Parameter)
            .filter(
                Parameter.endpoint_id == endpoint_id,
                Parameter.name == name,
                Parameter.param_type == param_type,
            )
            .first()
        )
        if existing:
            return existing

        param = Parameter(
            assessment_id=assessment_id,
            endpoint_id=endpoint_id,
            name=name,
            param_type=param_type,
            example_value=example_value,
        )
        self.session.add(param)
        self.session.commit()
        self.session.refresh(param)
        return param

    def add_js_asset(
        self,
        assessment_id: str,
        url: str,
        host: str,
        endpoints_found: Optional[List[str]] = None,
        routes_found: Optional[List[str]] = None,
        secrets_found: Optional[List[Dict[str, str]]] = None,
        source_map_url: Optional[str] = None,
    ) -> JavaScriptAsset:
        existing = (
            self.session.query(JavaScriptAsset)
            .filter(JavaScriptAsset.assessment_id == assessment_id, JavaScriptAsset.url == url)
            .first()
        )
        ep_json = json.dumps(endpoints_found) if endpoints_found else None
        rt_json = json.dumps(routes_found) if routes_found else None
        sec_json = json.dumps(secrets_found) if secrets_found else None

        if existing:
            existing.endpoints_found_json = ep_json or existing.endpoints_found_json
            existing.routes_found_json = rt_json or existing.routes_found_json
            existing.secrets_found_json = sec_json or existing.secrets_found_json
            existing.source_map_url = source_map_url or existing.source_map_url
            self.session.commit()
            return existing

        js_asset = JavaScriptAsset(
            assessment_id=assessment_id,
            url=url,
            host=host,
            endpoints_found_json=ep_json,
            routes_found_json=rt_json,
            secrets_found_json=sec_json,
            source_map_url=source_map_url,
        )
        self.session.add(js_asset)
        self.session.commit()
        self.session.refresh(js_asset)
        return js_asset

    def add_technology(
        self,
        assessment_id: str,
        host: str,
        name: str,
        category: str = "Web Server",
        version: Optional[str] = None,
        confidence: str = "CONFIRMED",
        detection_source: str = "HTTP_HEADER",
    ) -> Technology:
        existing = (
            self.session.query(Technology)
            .filter(
                Technology.assessment_id == assessment_id,
                Technology.host == host,
                Technology.name == name,
            )
            .first()
        )
        if existing:
            if version and not existing.version:
                existing.version = version
            self.session.commit()
            return existing

        tech = Technology(
            assessment_id=assessment_id,
            host=host,
            name=name,
            category=category,
            version=version,
            confidence=confidence,
            detection_source=detection_source,
        )
        self.session.add(tech)
        self.session.commit()
        self.session.refresh(tech)
        return tech

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
