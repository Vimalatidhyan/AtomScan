"""Technieum Enterprise v2.0 — SQLAlchemy ORM models.

Contains all 25 database models for the ASM scanning platform,
organized into five groups:

1. Core Scanning (ScanRun, Subdomain, PortScan, Vulnerability, HTTPHeader)
2. Intelligence (Technology, DomainTechnology, VulnerabilityMetadata,
   DNSRecord, ISPLocation, ThreatIntelData)
3. Compliance & Reporting (ComplianceReport, ComplianceFinding,
   RiskScore, AuditLog, AssetSnapshot)
4. Change Tracking (AssetChange, ChangeNotification, WebsiteSnapshot)
5. Integration & System (ScannerIntegration, ScanRunnerMetadata,
   APIKey, SavedReport, ScheduledScan, KnownVulnerability)
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import backref, relationship

from app.db.base import Base


# ---------------------------------------------------------------------------
# Group 1: Core Scanning Models
# ---------------------------------------------------------------------------


class ScanRun(Base):
    """Represents a single domain scanning operation.

    Each scan tracks one target domain through all 9 phases:
    discovery, port scanning, vulnerability detection, threat intel,
    risk scoring, change detection, compliance mapping, attack graph,
    and continuous monitoring.
    """

    __tablename__ = "scan_runs"

    id: int = Column(Integer, primary_key=True)
    domain: str = Column(String(255), nullable=False, index=True)
    scan_type: str = Column(String(50), default="full")
    status: str = Column(String(50), default="pending")
    created_at: datetime = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at: Optional[datetime] = Column(DateTime, nullable=True)
    risk_score: Optional[int] = Column(Integer, nullable=True)
    phase: int = Column(Integer, default=0)

    # Relationships
    subdomains = relationship(
        "Subdomain", back_populates="scan_run", cascade="all, delete-orphan"
    )
    vulnerabilities = relationship(
        "Vulnerability", back_populates="scan_run", cascade="all, delete-orphan"
    )
    dns_records = relationship(
        "DNSRecord", back_populates="scan_run", cascade="all, delete-orphan"
    )
    compliance_reports = relationship(
        "ComplianceReport",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    domain_technologies = relationship(
        "DomainTechnology",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    isp_locations = relationship(
        "ISPLocation", back_populates="scan_run", cascade="all, delete-orphan"
    )
    risk_scores = relationship(
        "RiskScore", back_populates="scan_run", cascade="all, delete-orphan"
    )
    asset_snapshots = relationship(
        "AssetSnapshot",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    scanner_metadata = relationship(
        "ScanRunnerMetadata",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )
    saved_reports = relationship(
        "SavedReport", back_populates="scan_run", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_scan_runs_domain_created", "domain", "created_at"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ScanRun(id={self.id}, domain={self.domain}, "
            f"status={self.status})>"
        )


class Subdomain(Base):
    """Discovered subdomain under a target domain.

    Tracks alive status and how the subdomain was discovered
    (passive DNS, active enumeration, or crawling).
    """

    __tablename__ = "subdomains"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    subdomain: str = Column(String(255), nullable=False)
    is_alive: bool = Column(Boolean, default=False)
    discovered_method: Optional[str] = Column(String(50), nullable=True)
    first_seen: datetime = Column(DateTime, default=datetime.utcnow)
    last_seen: Optional[datetime] = Column(DateTime, nullable=True)
    priority: int = Column(Integer, default=0)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="subdomains")
    port_scans = relationship(
        "PortScan", back_populates="subdomain", cascade="all, delete-orphan"
    )
    vulnerabilities = relationship(
        "Vulnerability", back_populates="subdomain"
    )
    http_headers = relationship(
        "HTTPHeader",
        back_populates="subdomain",
        cascade="all, delete-orphan",
    )
    website_snapshots = relationship(
        "WebsiteSnapshot",
        back_populates="subdomain",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_subdomains_scan_subdomain", "scan_run_id", "subdomain"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<Subdomain(id={self.id}, subdomain={self.subdomain}, "
            f"is_alive={self.is_alive})>"
        )


class PortScan(Base):
    """Port scan result for a subdomain.

    Tracks open ports, services, versions, and state. Used to
    identify the attack surface of each discovered host.
    """

    __tablename__ = "port_scans"

    id: int = Column(Integer, primary_key=True)
    subdomain_id: int = Column(
        Integer, ForeignKey("subdomains.id"), nullable=False, index=True
    )
    port: int = Column(Integer, nullable=False)
    protocol: str = Column(String(10), default="tcp")
    state: str = Column(String(50), default="closed")
    service: Optional[str] = Column(String(100), nullable=True)
    version: Optional[str] = Column(String(100), nullable=True)
    scanned_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    subdomain = relationship("Subdomain", back_populates="port_scans")
    vulnerabilities = relationship(
        "Vulnerability", back_populates="port_scan"
    )

    __table_args__ = (
        Index("idx_port_scans_subdomain_port", "subdomain_id", "port"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<PortScan(port={self.port}, service={self.service}, "
            f"state={self.state})>"
        )


class Vulnerability(Base):
    """Security finding from scanning.

    Can be port-based (weak cipher), web-based (XSS), or
    service-based (unpatched software). Links to scan run,
    subdomain, and optionally a specific port.
    """

    __tablename__ = "vulnerabilities"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    subdomain_id: Optional[int] = Column(
        Integer, ForeignKey("subdomains.id"), nullable=True, index=True
    )
    port_scan_id: Optional[int] = Column(
        Integer, ForeignKey("port_scans.id"), nullable=True, index=True
    )
    vuln_type: str = Column(String(100), nullable=False)
    severity: Optional[int] = Column(Integer, nullable=True)
    title: str = Column(String(255), nullable=False)
    description: Optional[str] = Column(String(2000), nullable=True)
    remediation: Optional[str] = Column(String(2000), nullable=True)
    discovered_at: datetime = Column(DateTime, default=datetime.utcnow)
    cve_ids: Optional[str] = Column(String(1000), nullable=True)
    risk_score: Optional[int] = Column(Integer, nullable=True)
    status: Optional[str] = Column(String(50), nullable=True, default="open")

    # Relationships
    scan_run = relationship("ScanRun", back_populates="vulnerabilities")
    subdomain = relationship("Subdomain", back_populates="vulnerabilities")
    port_scan = relationship("PortScan", back_populates="vulnerabilities")
    vuln_metadata = relationship(
        "VulnerabilityMetadata",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )
    threat_intel = relationship(
        "ThreatIntelData", back_populates="vulnerability"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<Vulnerability(id={self.id}, type={self.vuln_type}, "
            f"severity={self.severity})>"
        )


class HTTPHeader(Base):
    """HTTP response header captured from a subdomain.

    Used to detect technology stack, security header presence,
    and server configuration information.
    """

    __tablename__ = "http_headers"

    id: int = Column(Integer, primary_key=True)
    subdomain_id: int = Column(
        Integer, ForeignKey("subdomains.id"), nullable=False, index=True
    )
    header_name: str = Column(String(255), nullable=False)
    header_value: str = Column(String(2000), nullable=False)
    discovered_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    subdomain = relationship("Subdomain", back_populates="http_headers")

    __table_args__ = (
        Index("idx_http_headers_subdomain_name", "subdomain_id", "header_name"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<HTTPHeader(name={self.header_name}, "
            f"value={self.header_value[:50]})>"
        )


# ---------------------------------------------------------------------------
# Group 2: Intelligence Models
# ---------------------------------------------------------------------------


class Technology(Base):
    """Technology catalog entry.

    A shared registry of technologies like Apache, Nginx, WordPress,
    Node.js, Django, etc. Reusable across all scans via the
    DomainTechnology junction table.
    """

    __tablename__ = "technologies"

    id: int = Column(Integer, primary_key=True)
    name: str = Column(String(100), nullable=False, unique=True)
    category: str = Column(String(50), nullable=False)
    type: str = Column(String(50), nullable=False)
    cpes: Optional[str] = Column(String(1000), nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    domain_technologies = relationship(
        "DomainTechnology", back_populates="technology"
    )
    known_vulnerabilities = relationship(
        "KnownVulnerability",
        back_populates="technology",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<Technology(name={self.name}, category={self.category})>"
        )


class DomainTechnology(Base):
    """Junction table linking scan runs to detected technologies.

    Records which technologies were found during a scan, along with
    detected version, discovery method, and confidence level.
    """

    __tablename__ = "domain_technologies"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    technology_id: int = Column(
        Integer, ForeignKey("technologies.id"), nullable=False, index=True
    )
    version: Optional[str] = Column(String(100), nullable=True)
    discovered_method: Optional[str] = Column(String(100), nullable=True)
    confidence: int = Column(Integer, default=100)
    discovered_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="domain_technologies")
    technology = relationship(
        "Technology", back_populates="domain_technologies"
    )

    __table_args__ = (
        UniqueConstraint(
            "scan_run_id", "technology_id", name="uq_scan_technology"
        ),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<DomainTechnology(technology_id={self.technology_id}, "
            f"version={self.version})>"
        )


class VulnerabilityMetadata(Base):
    """Enriched vulnerability data from external sources.

    Links to CVE database, CVSS v3.1 scores, EPSS exploit
    probability, CISA KEV status, and Metasploit module
    availability.
    """

    __tablename__ = "vulnerability_metadata"

    id: int = Column(Integer, primary_key=True)
    vulnerability_id: int = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True
    )
    cve_id: Optional[str] = Column(String(50), nullable=True)
    cvss_v31_score: Optional[float] = Column(Float, nullable=True)
    cvss_v31_vector: Optional[str] = Column(String(100), nullable=True)
    epss_score: Optional[float] = Column(Float, nullable=True)
    in_kev: bool = Column(Boolean, default=False)
    has_metasploit: bool = Column(Boolean, default=False)
    active_exploitation: bool = Column(Boolean, default=False)
    days_since_published: Optional[int] = Column(Integer, nullable=True)
    affected_versions: Optional[str] = Column(String(1000), nullable=True)
    source: Optional[str] = Column(String(100), nullable=True)
    checked_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="vuln_metadata")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<VulnerabilityMetadata(cve={self.cve_id}, "
            f"cvss={self.cvss_v31_score})>"
        )


class DNSRecord(Base):
    """DNS record discovered during scanning.

    Tracks all DNS data (A, AAAA, CNAME, MX, TXT, NS, SOA)
    about the target domain and its subdomains.
    """

    __tablename__ = "dns_records"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    domain: str = Column(String(255), nullable=False)
    record_type: str = Column(String(10), nullable=False)
    value: str = Column(String(1000), nullable=False)
    ttl: Optional[int] = Column(Integer, nullable=True)
    discovered_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="dns_records")

    __table_args__ = (
        Index("idx_dns_records_domain_type", "domain", "record_type"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<DNSRecord(type={self.record_type}, value={self.value})>"
        )


class ISPLocation(Base):
    """IP geolocation and ISP information.

    Records the ISP, country, region, city, and coordinates
    for IP addresses discovered during scanning.
    """

    __tablename__ = "isp_locations"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    ip_address: str = Column(String(45), nullable=False)
    isp_name: Optional[str] = Column(String(255), nullable=True)
    country: Optional[str] = Column(String(100), nullable=True)
    region: Optional[str] = Column(String(100), nullable=True)
    city: Optional[str] = Column(String(100), nullable=True)
    latitude: Optional[float] = Column(Float, nullable=True)
    longitude: Optional[float] = Column(Float, nullable=True)
    discovered_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="isp_locations")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ISPLocation(ip={self.ip_address}, "
            f"country={self.country})>"
        )


class ThreatIntelData(Base):
    """External threat intelligence indicator.

    Stores threat indicators from sources like AbuseIPDB,
    VirusTotal, GreyNoise, etc. Can be linked to a specific
    vulnerability or stand alone.
    """

    __tablename__ = "threat_intel_data"

    id: int = Column(Integer, primary_key=True)
    vulnerability_id: Optional[int] = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True
    )
    indicator_type: str = Column(String(50), nullable=False)
    indicator_value: str = Column(String(500), nullable=False)
    severity: Optional[int] = Column(Integer, nullable=True)
    source: str = Column(String(100), nullable=False)
    description: Optional[str] = Column(Text, nullable=True)
    last_updated: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    vulnerability = relationship(
        "Vulnerability", back_populates="threat_intel"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ThreatIntelData(type={self.indicator_type}, "
            f"source={self.source})>"
        )


# ---------------------------------------------------------------------------
# Group 3: Compliance & Reporting Models
# ---------------------------------------------------------------------------


class ComplianceReport(Base):
    """Compliance report generated for a scan run.

    Aggregates compliance check results against frameworks
    like PCI-DSS, HIPAA, GDPR, ISO 27001, SOC 2, and NIST CSF.
    """

    __tablename__ = "compliance_reports"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    report_type: str = Column(String(50), nullable=False)
    generated_at: datetime = Column(DateTime, default=datetime.utcnow)
    passed_checks: int = Column(Integer, default=0)
    failed_checks: int = Column(Integer, default=0)
    overall_score: Optional[int] = Column(Integer, nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="compliance_reports")
    findings = relationship(
        "ComplianceFinding",
        back_populates="report",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ComplianceReport(type={self.report_type}, "
            f"score={self.overall_score})>"
        )


class ComplianceFinding(Base):
    """Individual compliance check result within a report.

    Represents a single requirement check (e.g. PCI-DSS-6.2)
    with its pass/fail status, evidence, and remediation guidance.
    """

    __tablename__ = "compliance_findings"

    id: int = Column(Integer, primary_key=True)
    report_id: int = Column(
        Integer,
        ForeignKey("compliance_reports.id"),
        nullable=False,
        index=True,
    )
    requirement_id: str = Column(String(50), nullable=False)
    control_name: str = Column(String(255), nullable=False)
    status: str = Column(String(20), nullable=False)
    evidence: Optional[str] = Column(Text, nullable=True)
    remediation: Optional[str] = Column(Text, nullable=True)
    severity: Optional[str] = Column(String(20), nullable=True)

    # Relationships
    report = relationship("ComplianceReport", back_populates="findings")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ComplianceFinding(req={self.requirement_id}, "
            f"status={self.status})>"
        )


class RiskScore(Base):
    """Calculated risk summary for a scan run.

    Aggregates vulnerability counts by severity tier and computes
    an overall risk score for executive reporting.
    """

    __tablename__ = "risk_scores"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    calculation_method: str = Column(String(50), nullable=False)
    critical_count: int = Column(Integer, default=0)
    high_count: int = Column(Integer, default=0)
    medium_count: int = Column(Integer, default=0)
    low_count: int = Column(Integer, default=0)
    overall_score: int = Column(Integer, default=0)
    calculated_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="risk_scores")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<RiskScore(score={self.overall_score}, "
            f"method={self.calculation_method})>"
        )


class AuditLog(Base):
    """Audit trail entry for compliance and debugging.

    Records who performed what action, on which entity,
    and when. Standalone model with no foreign key dependencies.
    """

    __tablename__ = "audit_logs"

    id: int = Column(Integer, primary_key=True)
    user: str = Column(String(255), nullable=False)
    action: str = Column(String(100), nullable=False)
    entity_type: str = Column(String(100), nullable=False)
    entity_id: Optional[int] = Column(Integer, nullable=True)
    details: Optional[str] = Column(Text, nullable=True)
    timestamp: datetime = Column(
        DateTime, default=datetime.utcnow, index=True
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<AuditLog(user={self.user}, action={self.action}, "
            f"entity={self.entity_type})>"
        )


class AssetSnapshot(Base):
    """Point-in-time snapshot of asset counts for trending.

    Records subdomain, port, and vulnerability counts at a
    specific date so that changes can be tracked over time.
    """

    __tablename__ = "asset_snapshots"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    snapshot_date: datetime = Column(DateTime, default=datetime.utcnow)
    domain_count: int = Column(Integer, default=0)
    subdomain_count: int = Column(Integer, default=0)
    open_port_count: int = Column(Integer, default=0)
    vulnerability_count: int = Column(Integer, default=0)
    critical_vuln_count: int = Column(Integer, default=0)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="asset_snapshots")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<AssetSnapshot(date={self.snapshot_date}, "
            f"vulns={self.vulnerability_count})>"
        )


# ---------------------------------------------------------------------------
# Group 4: Change Tracking Models
# ---------------------------------------------------------------------------


class AssetChange(Base):
    """Change detected between two asset snapshots.

    Highlights new subdomains, removed ports, modified
    technologies, or new vulnerabilities between scan runs.
    """

    __tablename__ = "asset_changes"

    id: int = Column(Integer, primary_key=True)
    previous_snapshot_id: int = Column(
        Integer, ForeignKey("asset_snapshots.id"), nullable=False, index=True
    )
    current_snapshot_id: int = Column(
        Integer, ForeignKey("asset_snapshots.id"), nullable=False, index=True
    )
    change_type: str = Column(String(20), nullable=False)
    asset_type: str = Column(String(50), nullable=False)
    description: Optional[str] = Column(Text, nullable=True)
    severity: Optional[str] = Column(String(20), nullable=True)
    detected_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    previous_snapshot = relationship(
        "AssetSnapshot", foreign_keys=[previous_snapshot_id]
    )
    current_snapshot = relationship(
        "AssetSnapshot", foreign_keys=[current_snapshot_id]
    )
    notifications = relationship(
        "ChangeNotification",
        back_populates="asset_change",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<AssetChange(type={self.change_type}, "
            f"asset={self.asset_type})>"
        )


class ChangeNotification(Base):
    """Alert delivery record for an asset change.

    Tracks notification delivery via email, webhook, or Slack
    with status tracking for retry logic.
    """

    __tablename__ = "change_notifications"

    id: int = Column(Integer, primary_key=True)
    asset_change_id: int = Column(
        Integer, ForeignKey("asset_changes.id"), nullable=False, index=True
    )
    notification_type: str = Column(String(20), nullable=False)
    recipient: str = Column(String(255), nullable=False)
    sent_at: Optional[datetime] = Column(DateTime, nullable=True)
    status: str = Column(String(20), default="pending")

    # Relationships
    asset_change = relationship(
        "AssetChange", back_populates="notifications"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ChangeNotification(type={self.notification_type}, "
            f"status={self.status})>"
        )


class WebsiteSnapshot(Base):
    """Website content snapshot for defacement detection.

    Stores content hash, HTTP status, and screenshot path
    to detect changes in website appearance or content.
    """

    __tablename__ = "website_snapshots"

    id: int = Column(Integer, primary_key=True)
    subdomain_id: int = Column(
        Integer, ForeignKey("subdomains.id"), nullable=False, index=True
    )
    captured_at: datetime = Column(DateTime, default=datetime.utcnow)
    http_status: Optional[int] = Column(Integer, nullable=True)
    content_hash: Optional[str] = Column(String(64), nullable=True)
    screenshot_path: Optional[str] = Column(String(500), nullable=True)
    crawl_depth: int = Column(Integer, default=0)

    # Relationships
    subdomain = relationship(
        "Subdomain", back_populates="website_snapshots"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<WebsiteSnapshot(subdomain_id={self.subdomain_id}, "
            f"status={self.http_status})>"
        )


# ---------------------------------------------------------------------------
# Group 5: Integration & System Models
# ---------------------------------------------------------------------------


class ScannerIntegration(Base):
    """External scanner configuration.

    Defines available scanners (Nmap, Burp, Nuclei, Trivy, etc.)
    with their API endpoints and health status.
    """

    __tablename__ = "scanner_integrations"

    id: int = Column(Integer, primary_key=True)
    name: str = Column(String(100), nullable=False, unique=True)
    api_endpoint: Optional[str] = Column(String(500), nullable=True)
    status: str = Column(String(20), default="active")
    last_check_time: Optional[datetime] = Column(DateTime, nullable=True)
    error_message: Optional[str] = Column(Text, nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    runner_metadata = relationship(
        "ScanRunnerMetadata", back_populates="scanner_integration"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ScannerIntegration(name={self.name}, "
            f"status={self.status})>"
        )


class ScanRunnerMetadata(Base):
    """Record of which scanner executed during a scan run.

    Tracks execution time, status, and the location of
    raw result files for each scanner invocation.
    """

    __tablename__ = "scan_runner_metadata"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    scanner_integration_id: int = Column(
        Integer,
        ForeignKey("scanner_integrations.id"),
        nullable=False,
        index=True,
    )
    scanner_name: str = Column(String(100), nullable=False)
    executed_at: datetime = Column(DateTime, default=datetime.utcnow)
    completed_at: Optional[datetime] = Column(DateTime, nullable=True)
    status: str = Column(String(20), default="pending")
    raw_results_file: Optional[str] = Column(String(500), nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="scanner_metadata")
    scanner_integration = relationship(
        "ScannerIntegration", back_populates="runner_metadata"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ScanRunnerMetadata(scanner={self.scanner_name}, "
            f"status={self.status})>"
        )


class APIKey(Base):
    """API authentication key for external integrations.

    Stores hashed keys with expiration, usage tracking,
    and rate limiting support.
    """

    __tablename__ = "api_keys"

    id: int = Column(Integer, primary_key=True)
    user_identifier: str = Column(String(255), nullable=False, index=True)
    key_hash: str = Column(String(255), nullable=False)
    name: str = Column(String(100), nullable=False)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    expires_at: Optional[datetime] = Column(DateTime, nullable=True)
    last_used: Optional[datetime] = Column(DateTime, nullable=True)
    is_active: bool = Column(Boolean, default=True)

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<APIKey(name={self.name}, user={self.user_identifier}, "
            f"active={self.is_active})>"
        )


class SavedReport(Base):
    """Generated report stored for download.

    Supports multiple formats (PDF, HTML, JSON, CSV) and
    tracks who generated the report and when.
    """

    __tablename__ = "saved_reports"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    report_type: str = Column(String(50), nullable=False)
    format: str = Column(String(10), nullable=False)
    file_path: str = Column(String(500), nullable=False)
    generated_by: Optional[str] = Column(String(255), nullable=True)
    generated_at: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_run = relationship("ScanRun", back_populates="saved_reports")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<SavedReport(type={self.report_type}, "
            f"format={self.format})>"
        )


class ScheduledScan(Base):
    """Recurring scan configuration for continuous monitoring.

    Defines domain targets with scan frequency (daily, weekly,
    monthly) and tracks next/last execution times.
    """

    __tablename__ = "scheduled_scans"

    id: int = Column(Integer, primary_key=True)
    domain: str = Column(String(255), nullable=False, index=True)
    scan_type: str = Column(String(50), default="full")
    frequency: str = Column(String(20), nullable=False)
    next_run: Optional[datetime] = Column(DateTime, nullable=True)
    last_run: Optional[datetime] = Column(DateTime, nullable=True)
    is_active: bool = Column(Boolean, default=True)
    created_by: Optional[str] = Column(String(255), nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ScheduledScan(domain={self.domain}, "
            f"frequency={self.frequency})>"
        )


class KnownVulnerability(Base):
    """Known CVE linked to a specific technology.

    Tracks CVEs associated with technologies (e.g. Apache, Nginx)
    so that detected tech stacks can be correlated with known
    security issues.
    """

    __tablename__ = "known_vulnerabilities"

    id: int = Column(Integer, primary_key=True)
    technology_id: int = Column(
        Integer, ForeignKey("technologies.id"), nullable=False, index=True
    )
    cve_id: str = Column(String(50), nullable=False)
    vuln_name: str = Column(String(255), nullable=False)
    severity: Optional[int] = Column(Integer, nullable=True)
    advisory_url: Optional[str] = Column(String(500), nullable=True)
    affected_versions: Optional[str] = Column(String(1000), nullable=True)
    fixed_version: Optional[str] = Column(String(100), nullable=True)
    published_at: Optional[datetime] = Column(DateTime, nullable=True)

    # Relationships
    technology = relationship(
        "Technology", back_populates="known_vulnerabilities"
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<KnownVulnerability(cve={self.cve_id}, "
            f"name={self.vuln_name})>"
        )


# ---------------------------------------------------------------------------
# Supplementary Models — Phase 3-5 support
# ---------------------------------------------------------------------------


class ServiceSignature(Base):
    """Service fingerprint signature.

    Used to identify services from banners and port/protocol combinations.
    """

    __tablename__ = "service_signatures"

    id: int = Column(Integer, primary_key=True)
    port: int = Column(Integer, nullable=False)
    protocol: str = Column(String(10), nullable=False)
    service_name: str = Column(String(100), nullable=False)
    banner_pattern: Optional[str] = Column(String(500), nullable=True)
    version_pattern: Optional[str] = Column(String(500), nullable=True)
    confidence: int = Column(Integer, default=80)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("port", "protocol", "service_name", name="uq_service_sig"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ServiceSignature(service={self.service_name}, port={self.port})>"
        )


class VendorMetadata(Base):
    """Organization/vendor metadata for TPRM.

    Tracks breach history, reputation, and response times.
    """

    __tablename__ = "vendor_metadata"

    id: int = Column(Integer, primary_key=True)
    org_name: str = Column(String(255), nullable=False, unique=True)
    website: Optional[str] = Column(String(255), nullable=True)
    industry: Optional[str] = Column(String(100), nullable=True)
    founded_year: Optional[int] = Column(Integer, nullable=True)
    employee_count: Optional[str] = Column(String(50), nullable=True)
    headquarters_country: Optional[str] = Column(String(2), nullable=True)
    breach_history: int = Column(Integer, default=0)
    last_breach_date: Optional[datetime] = Column(DateTime, nullable=True)
    breach_summary: Optional[str] = Column(String(1000), nullable=True)
    mean_time_to_repair: Optional[int] = Column(Integer, nullable=True)
    mean_time_to_detect: Optional[int] = Column(Integer, nullable=True)
    security_score: Optional[int] = Column(Integer, nullable=True)
    reputation_score: Optional[int] = Column(Integer, nullable=True)
    notes: Optional[str] = Column(String(2000), nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    updated_at: datetime = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<VendorMetadata(org={self.org_name}, breaches={self.breach_history})>"
        )


class DataLeak(Base):
    """Leaked credentials and breach data.

    Tracks exposed emails and passwords from data breaches.
    """

    __tablename__ = "data_leaks"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    email: str = Column(String(255), nullable=False)
    breach_name: str = Column(String(255), nullable=False)
    breach_date: Optional[datetime] = Column(DateTime, nullable=True)
    exposed_data: Optional[str] = Column(String(500), nullable=True)
    password_hash: Optional[str] = Column(String(255), nullable=True)
    source_url: Optional[str] = Column(String(500), nullable=True)
    is_verified: bool = Column(Boolean, default=False)
    is_exploited: bool = Column(Boolean, default=False)
    credentials_tested: bool = Column(Boolean, default=False)
    exploit_date: Optional[datetime] = Column(DateTime, nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", backref=backref("data_leaks", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("idx_data_leaks_email_breach", "email", "breach_date"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return f"<DataLeak(email={self.email}, breach={self.breach_name})>"


class ActiveExploit(Base):
    """Public exploits for vulnerabilities.

    Tracks Metasploit modules, PoCs, and active exploitation status.
    """

    __tablename__ = "active_exploits"

    id: int = Column(Integer, primary_key=True)
    vulnerability_id: int = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True
    )
    cve_id: Optional[str] = Column(String(50), nullable=True)
    exploit_id: Optional[str] = Column(String(100), nullable=True)
    exploit_title: str = Column(String(255), nullable=False)
    exploit_source: str = Column(String(100), nullable=False)
    exploit_type: Optional[str] = Column(String(50), nullable=True)
    release_date: Optional[datetime] = Column(DateTime, nullable=True)
    is_public: bool = Column(Boolean, default=True)
    is_actively_exploited: bool = Column(Boolean, default=False)
    exploitation_reports: int = Column(Integer, default=0)
    proof_of_concept: bool = Column(Boolean, default=False)
    proof_of_concept_url: Optional[str] = Column(String(500), nullable=True)
    difficulty: Optional[str] = Column(String(20), nullable=True)
    popularity_score: Optional[int] = Column(Integer, nullable=True)
    last_updated: datetime = Column(DateTime, default=datetime.utcnow)

    # Relationships
    vulnerability = relationship("Vulnerability", backref="active_exploits")

    __table_args__ = (
        Index("idx_active_exploits_vuln_source", "vulnerability_id", "exploit_source"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return f"<ActiveExploit(cve={self.cve_id}, source={self.exploit_source})>"


class MalwareIndicator(Base):
    """Malware indicators (hashes, domains, IPs).

    Tracks IOCs from threat feeds.
    """

    __tablename__ = "malware_indicators"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    indicator_type: str = Column(String(50), nullable=False)
    indicator_value: str = Column(String(500), nullable=False)
    hash_type: Optional[str] = Column(String(10), nullable=True)
    malware_family: Optional[str] = Column(String(100), nullable=True)
    yara_rule: Optional[str] = Column(String(1000), nullable=True)
    detection_count: int = Column(Integer, default=0)
    first_submission: Optional[datetime] = Column(DateTime, nullable=True)
    last_analysis: datetime = Column(DateTime, default=datetime.utcnow)
    verdict: Optional[str] = Column(String(50), nullable=True)
    analyzed_by: Optional[str] = Column(String(100), nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", backref=backref("malware_indicators", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("idx_malware_type_value", "indicator_type", "indicator_value"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<MalwareIndicator(type={self.indicator_type}, "
            f"value={self.indicator_value[:30]})>"
        )


class ComplianceEvidence(Base):
    """Evidence linking findings to compliance controls.

    Tracks remediation and verification for audit trails.
    """

    __tablename__ = "compliance_evidence"

    id: int = Column(Integer, primary_key=True)
    compliance_report_id: int = Column(
        Integer, ForeignKey("compliance_reports.id"), nullable=False, index=True
    )
    compliance_finding_id: Optional[int] = Column(
        Integer, ForeignKey("compliance_findings.id"), nullable=True, index=True
    )
    vulnerability_id: Optional[int] = Column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=True, index=True
    )
    evidence_type: str = Column(String(50), nullable=False)
    description: str = Column(String(1000), nullable=False)
    evidence_file: Optional[str] = Column(String(255), nullable=True)
    collected_date: datetime = Column(DateTime, default=datetime.utcnow)
    verified: bool = Column(Boolean, default=False)
    verifier_name: Optional[str] = Column(String(255), nullable=True)
    verification_date: Optional[datetime] = Column(DateTime, nullable=True)

    # Relationships
    compliance_report = relationship("ComplianceReport", backref="compliance_evidence_items")
    compliance_finding = relationship("ComplianceFinding", backref="compliance_evidence_items")
    vulnerability = relationship("Vulnerability", backref="compliance_evidence")

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ComplianceEvidence(report_id={self.compliance_report_id}, "
            f"type={self.evidence_type})>"
        )


class BaselineSnapshot(Base):
    """Scan snapshot for baseline comparison and change detection.

    Used for drift analysis between scan runs.
    """

    __tablename__ = "baseline_snapshots"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    snapshot_date: datetime = Column(DateTime, default=datetime.utcnow)
    is_baseline: bool = Column(Boolean, default=False)
    asset_count: Optional[int] = Column(Integer, nullable=True)
    subdomain_count: Optional[int] = Column(Integer, nullable=True)
    port_count: Optional[int] = Column(Integer, nullable=True)
    vulnerability_count: Optional[int] = Column(Integer, nullable=True)
    technology_count: Optional[int] = Column(Integer, nullable=True)
    risk_score_snapshot: Optional[int] = Column(Integer, nullable=True)
    snapshot_data: Optional[str] = Column(Text, nullable=True)
    md5_hash: Optional[str] = Column(String(32), nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", backref=backref("baseline_snapshots", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("idx_baseline_scan_flag", "scan_run_id", "is_baseline"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<BaselineSnapshot(scan_run_id={self.scan_run_id}, "
            f"is_baseline={self.is_baseline})>"
        )


class ScanProgress(Base):
    """Real-time scan progress tracking.

    Updated during execution for monitoring dashboards.
    """

    __tablename__ = "scan_progress"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, unique=True, index=True
    )
    current_phase: int = Column(Integer, default=0)
    current_tool: Optional[str] = Column(String(100), nullable=True)
    progress_percentage: int = Column(Integer, default=0)
    status: str = Column(String(50), default="queued")
    subdomains_found: int = Column(Integer, default=0)
    ports_found: int = Column(Integer, default=0)
    vulnerabilities_found: int = Column(Integer, default=0)
    assets_added: int = Column(Integer, default=0)
    assets_removed: int = Column(Integer, default=0)
    last_update: datetime = Column(DateTime, default=datetime.utcnow)
    estimated_completion: Optional[datetime] = Column(DateTime, nullable=True)
    duration_seconds: Optional[int] = Column(Integer, nullable=True)

    # Relationships
    scan_run = relationship("ScanRun", backref=backref("scan_progress", cascade="all, delete-orphan"))

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<ScanProgress(scan_run_id={self.scan_run_id}, "
            f"phase={self.current_phase}, pct={self.progress_percentage})>"
        )


class CacheEntry(Base):
    """Query result cache.

    Reduces API calls and speeds up repeated queries.
    """

    __tablename__ = "cache_entries"

    id: int = Column(Integer, primary_key=True)
    cache_key: str = Column(String(500), nullable=False, unique=True)
    cache_value: str = Column(Text, nullable=False)
    source: str = Column(String(100), nullable=False)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    expires_at: Optional[datetime] = Column(DateTime, nullable=True)
    hit_count: int = Column(Integer, default=0)
    is_expired: bool = Column(Boolean, default=False)

    __table_args__ = (
        Index("idx_cache_key_expires", "cache_key", "expires_at"),
    )

    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"<CacheEntry(key={self.cache_key[:30]}, source={self.source})>"
        )


class Webhook(Base):
    """Webhook configuration for event notifications.

    Supports filtering by event types and stores delivery history.
    """

    __tablename__ = "webhooks"

    id: int = Column(Integer, primary_key=True)
    url: str = Column(String(500), nullable=False)
    events: str = Column(String(500), nullable=False)  # Comma-separated event types
    secret: Optional[str] = Column(String(255), nullable=True)
    active: bool = Column(Boolean, default=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    created_by: Optional[str] = Column(String(255), nullable=True)
    last_triggered: Optional[datetime] = Column(DateTime, nullable=True)
    success_count: int = Column(Integer, default=0)
    failure_count: int = Column(Integer, default=0)

    def __repr__(self) -> str:
        """Return string representation."""
        return f"<Webhook(id={self.id}, url={self.url[:50]}, active={self.active})>"


# ---------------------------------------------------------------------------
# Queue & Event Models (added Round 6 — prod hardening)
# ---------------------------------------------------------------------------


class ScanJob(Base):
    """Persistent job queue record — one row per enqueued scan execution.

    The Python worker polls this table for ``status='queued'`` rows, claims
    one atomically, and transitions it through queued → running → done/failed.
    """

    __tablename__ = "scan_jobs"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    status: str = Column(String(20), nullable=False, default="queued", index=True)
    worker_id: Optional[str] = Column(String(100), nullable=True)
    queued_at: datetime = Column(DateTime, default=datetime.utcnow)
    started_at: Optional[datetime] = Column(DateTime, nullable=True)
    finished_at: Optional[datetime] = Column(DateTime, nullable=True)
    error: Optional[str] = Column(Text, nullable=True)

    scan_run = relationship("ScanRun", backref=backref("scan_jobs", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("idx_scan_jobs_status_id", "status", "id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanJob(id={self.id}, scan_run_id={self.scan_run_id}, "
            f"status={self.status})>"
        )


class ScanEvent(Base):
    """Persisted scan event / log line for real-time streaming.

    The worker writes one row per output line from the scan harness.
    The SSE stream endpoint reads rows with ``id > last_seen_id`` and
    delivers them to the client — no synthetic data, no mocks.
    """

    __tablename__ = "scan_events"

    id: int = Column(Integer, primary_key=True)
    scan_run_id: int = Column(
        Integer, ForeignKey("scan_runs.id"), nullable=False, index=True
    )
    event_type: str = Column(String(50), nullable=False, default="log")
    level: str = Column(String(20), nullable=False, default="info")
    message: Optional[str] = Column(Text, nullable=True)
    data: Optional[str] = Column(Text, nullable=True)  # JSON-serialized extra fields
    phase: Optional[int] = Column(Integer, nullable=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)

    scan_run = relationship("ScanRun", backref=backref("scan_events", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("idx_scan_events_run_id", "scan_run_id", "id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanEvent(id={self.id}, scan_run_id={self.scan_run_id}, "
            f"type={self.event_type})>"
        )

