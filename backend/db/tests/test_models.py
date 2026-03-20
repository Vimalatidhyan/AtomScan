"""Comprehensive tests for all 25 Technieum database models.

Tests cover: model creation, default values, repr methods,
nullable constraints, relationships, composite indexes,
and unique constraints. Uses in-memory SQLite for speed.
"""

from datetime import datetime

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import Base
from app.db.models import (
    APIKey,
    AssetChange,
    AssetSnapshot,
    AuditLog,
    ChangeNotification,
    ComplianceFinding,
    ComplianceReport,
    DNSRecord,
    DomainTechnology,
    HTTPHeader,
    ISPLocation,
    KnownVulnerability,
    PortScan,
    RiskScore,
    SavedReport,
    ScannerIntegration,
    ScanRun,
    ScanRunnerMetadata,
    ScheduledScan,
    Subdomain,
    Technology,
    ThreatIntelData,
    Vulnerability,
    VulnerabilityMetadata,
    WebsiteSnapshot,
)


@pytest.fixture()
def engine():
    """Create an in-memory SQLite engine with all tables."""
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


@pytest.fixture()
def session(engine) -> Session:
    """Provide a transactional database session."""
    factory = sessionmaker(bind=engine)
    sess = factory()
    yield sess
    sess.close()


# ---------------------------------------------------------------------------
# Helper: create a full scan hierarchy for relationship tests
# ---------------------------------------------------------------------------


def _create_scan_run(session: Session, domain: str = "example.com") -> ScanRun:
    """Insert and return a ScanRun."""
    scan = ScanRun(domain=domain)
    session.add(scan)
    session.commit()
    return scan


def _create_subdomain(
    session: Session, scan_run: ScanRun, name: str = "api.example.com"
) -> Subdomain:
    """Insert and return a Subdomain."""
    sub = Subdomain(scan_run_id=scan_run.id, subdomain=name, is_alive=True)
    session.add(sub)
    session.commit()
    return sub


# ---------------------------------------------------------------------------
# Group 1: Core Scanning Models
# ---------------------------------------------------------------------------


class TestScanRun:
    """Tests for the ScanRun model."""

    def test_creation_with_defaults(self, session: Session) -> None:
        scan = ScanRun(domain="example.com")
        session.add(scan)
        session.commit()

        assert scan.id is not None
        assert scan.domain == "example.com"
        assert scan.scan_type == "full"
        assert scan.status == "pending"
        assert scan.phase == 0
        assert scan.risk_score is None
        assert scan.completed_at is None
        assert isinstance(scan.created_at, datetime)

    def test_creation_with_custom_values(self, session: Session) -> None:
        scan = ScanRun(
            domain="test.org",
            scan_type="quick",
            status="running",
            phase=3,
            risk_score=75,
        )
        session.add(scan)
        session.commit()

        assert scan.scan_type == "quick"
        assert scan.status == "running"
        assert scan.phase == 3
        assert scan.risk_score == 75

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        r = repr(scan)
        assert "ScanRun" in r
        assert "example.com" in r
        assert "pending" in r

    def test_subdomains_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = Subdomain(scan_run_id=scan.id, subdomain="www.example.com")
        session.add(sub)
        session.commit()

        assert len(scan.subdomains) == 1
        assert scan.subdomains[0].subdomain == "www.example.com"
        assert sub.scan_run.domain == "example.com"


class TestSubdomain:
    """Tests for the Subdomain model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = Subdomain(
            scan_run_id=scan.id,
            subdomain="api.example.com",
            is_alive=True,
            discovered_method="passive",
        )
        session.add(sub)
        session.commit()

        assert sub.id is not None
        assert sub.is_alive is True
        assert sub.discovered_method == "passive"
        assert sub.priority == 0

    def test_defaults(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = Subdomain(scan_run_id=scan.id, subdomain="mail.example.com")
        session.add(sub)
        session.commit()

        assert sub.is_alive is False
        assert sub.priority == 0
        assert sub.last_seen is None

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        r = repr(sub)
        assert "Subdomain" in r
        assert "api.example.com" in r

    def test_port_scans_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        port = PortScan(subdomain_id=sub.id, port=443, state="open")
        session.add(port)
        session.commit()

        assert len(sub.port_scans) == 1
        assert sub.port_scans[0].port == 443


class TestPortScan:
    """Tests for the PortScan model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        port = PortScan(
            subdomain_id=sub.id,
            port=80,
            protocol="tcp",
            state="open",
            service="HTTP",
            version="Apache 2.4.41",
        )
        session.add(port)
        session.commit()

        assert port.id is not None
        assert port.service == "HTTP"
        assert port.version == "Apache 2.4.41"

    def test_defaults(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        port = PortScan(subdomain_id=sub.id, port=22)
        session.add(port)
        session.commit()

        assert port.protocol == "tcp"
        assert port.state == "closed"
        assert port.service is None

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        port = PortScan(
            subdomain_id=sub.id, port=443, state="open", service="HTTPS"
        )
        session.add(port)
        session.commit()
        r = repr(port)
        assert "PortScan" in r
        assert "443" in r


class TestVulnerability:
    """Tests for the Vulnerability model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id,
            vuln_type="xss",
            title="Reflected XSS in search",
            severity=65,
            description="User input reflected without encoding",
            remediation="Sanitize output with HTML encoding",
            cve_ids="CVE-2021-1234",
        )
        session.add(vuln)
        session.commit()

        assert vuln.id is not None
        assert vuln.vuln_type == "xss"
        assert vuln.severity == 65

    def test_nullable_foreign_keys(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="weak_cipher", title="Weak TLS"
        )
        session.add(vuln)
        session.commit()

        assert vuln.subdomain_id is None
        assert vuln.port_scan_id is None

    def test_scan_run_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="sqli", title="SQL Injection"
        )
        session.add(vuln)
        session.commit()

        assert len(scan.vulnerabilities) == 1
        assert vuln.scan_run.domain == "example.com"

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id,
            vuln_type="rfi",
            title="Remote File Include",
            severity=90,
        )
        session.add(vuln)
        session.commit()
        r = repr(vuln)
        assert "Vulnerability" in r
        assert "rfi" in r


class TestHTTPHeader:
    """Tests for the HTTPHeader model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        header = HTTPHeader(
            subdomain_id=sub.id,
            header_name="Server",
            header_value="nginx/1.18.0",
        )
        session.add(header)
        session.commit()

        assert header.id is not None
        assert header.header_name == "Server"

    def test_repr_truncates_value(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        long_value = "A" * 200
        header = HTTPHeader(
            subdomain_id=sub.id,
            header_name="X-Custom",
            header_value=long_value,
        )
        session.add(header)
        session.commit()
        r = repr(header)
        assert "HTTPHeader" in r
        assert len(r) < 200

    def test_subdomain_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        h1 = HTTPHeader(
            subdomain_id=sub.id,
            header_name="Server",
            header_value="nginx",
        )
        h2 = HTTPHeader(
            subdomain_id=sub.id,
            header_name="X-Powered-By",
            header_value="PHP/7.4",
        )
        session.add_all([h1, h2])
        session.commit()

        assert len(sub.http_headers) == 2


# ---------------------------------------------------------------------------
# Group 2: Intelligence Models
# ---------------------------------------------------------------------------


class TestTechnology:
    """Tests for the Technology model."""

    def test_creation(self, session: Session) -> None:
        tech = Technology(
            name="Apache", category="web_server", type="software"
        )
        session.add(tech)
        session.commit()
        assert tech.id is not None
        assert tech.name == "Apache"

    def test_unique_name(self, session: Session) -> None:
        t1 = Technology(name="Nginx", category="web_server", type="software")
        session.add(t1)
        session.commit()

        t2 = Technology(name="Nginx", category="proxy", type="software")
        session.add(t2)
        with pytest.raises(Exception):
            session.commit()

    def test_repr(self, session: Session) -> None:
        tech = Technology(
            name="WordPress", category="cms", type="software"
        )
        session.add(tech)
        session.commit()
        assert "WordPress" in repr(tech)


class TestDomainTechnology:
    """Tests for the DomainTechnology junction model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        tech = Technology(
            name="React", category="framework", type="library"
        )
        session.add(tech)
        session.commit()

        dt = DomainTechnology(
            scan_run_id=scan.id,
            technology_id=tech.id,
            version="18.2.0",
            confidence=95,
        )
        session.add(dt)
        session.commit()

        assert dt.id is not None
        assert dt.confidence == 95

    def test_relationships(self, session: Session) -> None:
        scan = _create_scan_run(session)
        tech = Technology(
            name="Django", category="framework", type="software"
        )
        session.add(tech)
        session.commit()

        dt = DomainTechnology(
            scan_run_id=scan.id, technology_id=tech.id
        )
        session.add(dt)
        session.commit()

        assert dt.scan_run.domain == "example.com"
        assert dt.technology.name == "Django"
        assert len(scan.domain_technologies) == 1

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        tech = Technology(name="Vue", category="framework", type="library")
        session.add(tech)
        session.commit()
        dt = DomainTechnology(
            scan_run_id=scan.id, technology_id=tech.id, version="3.0"
        )
        session.add(dt)
        session.commit()
        assert "DomainTechnology" in repr(dt)


class TestVulnerabilityMetadata:
    """Tests for the VulnerabilityMetadata model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="rce", title="Remote Code Exec"
        )
        session.add(vuln)
        session.commit()

        meta = VulnerabilityMetadata(
            vulnerability_id=vuln.id,
            cve_id="CVE-2021-44228",
            cvss_v31_score=10.0,
            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            epss_score=0.975,
            in_kev=True,
            has_metasploit=True,
            active_exploitation=True,
            days_since_published=365,
            source="nuclei",
        )
        session.add(meta)
        session.commit()

        assert meta.cvss_v31_score == 10.0
        assert meta.in_kev is True
        assert meta.epss_score == 0.975

    def test_defaults(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="info", title="Info Disclosure"
        )
        session.add(vuln)
        session.commit()

        meta = VulnerabilityMetadata(vulnerability_id=vuln.id)
        session.add(meta)
        session.commit()

        assert meta.in_kev is False
        assert meta.has_metasploit is False
        assert meta.active_exploitation is False

    def test_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="xss", title="Stored XSS"
        )
        session.add(vuln)
        session.commit()

        meta = VulnerabilityMetadata(
            vulnerability_id=vuln.id, cve_id="CVE-2023-0001"
        )
        session.add(meta)
        session.commit()

        assert len(vuln.vuln_metadata) == 1
        assert vuln.vuln_metadata[0].cve_id == "CVE-2023-0001"

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="lfi", title="LFI"
        )
        session.add(vuln)
        session.commit()
        meta = VulnerabilityMetadata(
            vulnerability_id=vuln.id,
            cve_id="CVE-2024-9999",
            cvss_v31_score=7.5,
        )
        session.add(meta)
        session.commit()
        assert "CVE-2024-9999" in repr(meta)


class TestDNSRecord:
    """Tests for the DNSRecord model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        dns = DNSRecord(
            scan_run_id=scan.id,
            domain="example.com",
            record_type="A",
            value="93.184.216.34",
            ttl=3600,
        )
        session.add(dns)
        session.commit()

        assert dns.id is not None
        assert dns.record_type == "A"
        assert dns.ttl == 3600

    def test_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        dns = DNSRecord(
            scan_run_id=scan.id,
            domain="example.com",
            record_type="MX",
            value="mail.example.com",
        )
        session.add(dns)
        session.commit()

        assert len(scan.dns_records) == 1
        assert dns.scan_run.domain == "example.com"

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        dns = DNSRecord(
            scan_run_id=scan.id,
            domain="example.com",
            record_type="CNAME",
            value="cdn.example.com",
        )
        session.add(dns)
        session.commit()
        assert "CNAME" in repr(dns)


class TestISPLocation:
    """Tests for the ISPLocation model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        loc = ISPLocation(
            scan_run_id=scan.id,
            ip_address="93.184.216.34",
            isp_name="Edgecast",
            country="US",
            region="California",
            city="Los Angeles",
            latitude=34.0522,
            longitude=-118.2437,
        )
        session.add(loc)
        session.commit()

        assert loc.id is not None
        assert loc.latitude == 34.0522

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        loc = ISPLocation(
            scan_run_id=scan.id,
            ip_address="1.2.3.4",
            country="DE",
        )
        session.add(loc)
        session.commit()
        assert "1.2.3.4" in repr(loc)


class TestThreatIntelData:
    """Tests for the ThreatIntelData model."""

    def test_creation_standalone(self, session: Session) -> None:
        ti = ThreatIntelData(
            indicator_type="ip",
            indicator_value="192.168.1.100",
            severity=85,
            source="AbuseIPDB",
            description="Known C2 server",
        )
        session.add(ti)
        session.commit()

        assert ti.id is not None
        assert ti.vulnerability_id is None

    def test_linked_to_vulnerability(self, session: Session) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="c2", title="C2 Communication"
        )
        session.add(vuln)
        session.commit()

        ti = ThreatIntelData(
            vulnerability_id=vuln.id,
            indicator_type="domain",
            indicator_value="evil.example.com",
            source="VirusTotal",
        )
        session.add(ti)
        session.commit()

        assert len(vuln.threat_intel) == 1
        assert ti.vulnerability.title == "C2 Communication"

    def test_repr(self, session: Session) -> None:
        ti = ThreatIntelData(
            indicator_type="file_hash",
            indicator_value="abc123",
            source="GreyNoise",
        )
        session.add(ti)
        session.commit()
        assert "file_hash" in repr(ti)


# ---------------------------------------------------------------------------
# Group 3: Compliance & Reporting Models
# ---------------------------------------------------------------------------


class TestComplianceReport:
    """Tests for the ComplianceReport model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = ComplianceReport(
            scan_run_id=scan.id,
            report_type="pci-dss",
            passed_checks=45,
            failed_checks=5,
            overall_score=90,
        )
        session.add(report)
        session.commit()

        assert report.id is not None
        assert report.overall_score == 90

    def test_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = ComplianceReport(
            scan_run_id=scan.id, report_type="hipaa"
        )
        session.add(report)
        session.commit()

        assert len(scan.compliance_reports) == 1
        assert report.scan_run.domain == "example.com"

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = ComplianceReport(
            scan_run_id=scan.id,
            report_type="gdpr",
            overall_score=78,
        )
        session.add(report)
        session.commit()
        assert "gdpr" in repr(report)


class TestComplianceFinding:
    """Tests for the ComplianceFinding model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = ComplianceReport(
            scan_run_id=scan.id, report_type="pci-dss"
        )
        session.add(report)
        session.commit()

        finding = ComplianceFinding(
            report_id=report.id,
            requirement_id="PCI-DSS-6.2",
            control_name="Patch Management",
            status="failed",
            severity="high",
            remediation="Apply latest security patches",
        )
        session.add(finding)
        session.commit()

        assert finding.id is not None
        assert finding.status == "failed"

    def test_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = ComplianceReport(
            scan_run_id=scan.id, report_type="iso27001"
        )
        session.add(report)
        session.commit()

        f1 = ComplianceFinding(
            report_id=report.id,
            requirement_id="A.12.6.1",
            control_name="Technical Vulnerability Mgmt",
            status="passed",
        )
        f2 = ComplianceFinding(
            report_id=report.id,
            requirement_id="A.14.2.5",
            control_name="Secure Development",
            status="failed",
        )
        session.add_all([f1, f2])
        session.commit()

        assert len(report.findings) == 2

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = ComplianceReport(
            scan_run_id=scan.id, report_type="soc2"
        )
        session.add(report)
        session.commit()
        finding = ComplianceFinding(
            report_id=report.id,
            requirement_id="CC6.1",
            control_name="Logical Access",
            status="passed",
        )
        session.add(finding)
        session.commit()
        assert "CC6.1" in repr(finding)


class TestRiskScore:
    """Tests for the RiskScore model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        score = RiskScore(
            scan_run_id=scan.id,
            calculation_method="v2.0",
            critical_count=2,
            high_count=5,
            medium_count=12,
            low_count=30,
            overall_score=78,
        )
        session.add(score)
        session.commit()

        assert score.id is not None
        assert score.overall_score == 78
        assert score.critical_count == 2

    def test_defaults(self, session: Session) -> None:
        scan = _create_scan_run(session)
        score = RiskScore(
            scan_run_id=scan.id, calculation_method="v1.0"
        )
        session.add(score)
        session.commit()

        assert score.critical_count == 0
        assert score.overall_score == 0

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        score = RiskScore(
            scan_run_id=scan.id,
            calculation_method="v2.0",
            overall_score=55,
        )
        session.add(score)
        session.commit()
        assert "55" in repr(score)


class TestAuditLog:
    """Tests for the AuditLog model."""

    def test_creation(self, session: Session) -> None:
        log = AuditLog(
            user="admin@technieum.io",
            action="created_scan",
            entity_type="ScanRun",
            entity_id=1,
            details='{"domain": "example.com"}',
        )
        session.add(log)
        session.commit()

        assert log.id is not None
        assert isinstance(log.timestamp, datetime)

    def test_system_user(self, session: Session) -> None:
        log = AuditLog(
            user="system",
            action="auto_scan",
            entity_type="ScheduledScan",
        )
        session.add(log)
        session.commit()

        assert log.entity_id is None
        assert log.details is None

    def test_repr(self, session: Session) -> None:
        log = AuditLog(
            user="test", action="view", entity_type="Report"
        )
        session.add(log)
        session.commit()
        assert "test" in repr(log)


class TestAssetSnapshot:
    """Tests for the AssetSnapshot model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap = AssetSnapshot(
            scan_run_id=scan.id,
            subdomain_count=150,
            open_port_count=42,
            vulnerability_count=18,
            critical_vuln_count=3,
        )
        session.add(snap)
        session.commit()

        assert snap.id is not None
        assert snap.subdomain_count == 150

    def test_defaults(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap = AssetSnapshot(scan_run_id=scan.id)
        session.add(snap)
        session.commit()

        assert snap.domain_count == 0
        assert snap.critical_vuln_count == 0

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap = AssetSnapshot(
            scan_run_id=scan.id, vulnerability_count=5
        )
        session.add(snap)
        session.commit()
        assert "AssetSnapshot" in repr(snap)


# ---------------------------------------------------------------------------
# Group 4: Change Tracking Models
# ---------------------------------------------------------------------------


class TestAssetChange:
    """Tests for the AssetChange model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap1 = AssetSnapshot(scan_run_id=scan.id, subdomain_count=10)
        snap2 = AssetSnapshot(scan_run_id=scan.id, subdomain_count=15)
        session.add_all([snap1, snap2])
        session.commit()

        change = AssetChange(
            previous_snapshot_id=snap1.id,
            current_snapshot_id=snap2.id,
            change_type="new",
            asset_type="subdomain",
            description="5 new subdomains discovered",
            severity="medium",
        )
        session.add(change)
        session.commit()

        assert change.id is not None
        assert change.change_type == "new"

    def test_snapshot_relationships(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap1 = AssetSnapshot(scan_run_id=scan.id)
        snap2 = AssetSnapshot(scan_run_id=scan.id)
        session.add_all([snap1, snap2])
        session.commit()

        change = AssetChange(
            previous_snapshot_id=snap1.id,
            current_snapshot_id=snap2.id,
            change_type="removed",
            asset_type="port",
        )
        session.add(change)
        session.commit()

        assert change.previous_snapshot.id == snap1.id
        assert change.current_snapshot.id == snap2.id

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap1 = AssetSnapshot(scan_run_id=scan.id)
        snap2 = AssetSnapshot(scan_run_id=scan.id)
        session.add_all([snap1, snap2])
        session.commit()
        change = AssetChange(
            previous_snapshot_id=snap1.id,
            current_snapshot_id=snap2.id,
            change_type="modified",
            asset_type="vulnerability",
        )
        session.add(change)
        session.commit()
        assert "modified" in repr(change)


class TestChangeNotification:
    """Tests for the ChangeNotification model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap1 = AssetSnapshot(scan_run_id=scan.id)
        snap2 = AssetSnapshot(scan_run_id=scan.id)
        session.add_all([snap1, snap2])
        session.commit()

        change = AssetChange(
            previous_snapshot_id=snap1.id,
            current_snapshot_id=snap2.id,
            change_type="new",
            asset_type="vulnerability",
        )
        session.add(change)
        session.commit()

        notif = ChangeNotification(
            asset_change_id=change.id,
            notification_type="email",
            recipient="security@example.com",
            status="sent",
        )
        session.add(notif)
        session.commit()

        assert notif.id is not None
        assert notif.status == "sent"

    def test_default_status(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap1 = AssetSnapshot(scan_run_id=scan.id)
        snap2 = AssetSnapshot(scan_run_id=scan.id)
        session.add_all([snap1, snap2])
        session.commit()

        change = AssetChange(
            previous_snapshot_id=snap1.id,
            current_snapshot_id=snap2.id,
            change_type="new",
            asset_type="port",
        )
        session.add(change)
        session.commit()

        notif = ChangeNotification(
            asset_change_id=change.id,
            notification_type="slack",
            recipient="#security",
        )
        session.add(notif)
        session.commit()

        assert notif.status == "pending"

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        snap1 = AssetSnapshot(scan_run_id=scan.id)
        snap2 = AssetSnapshot(scan_run_id=scan.id)
        session.add_all([snap1, snap2])
        session.commit()
        change = AssetChange(
            previous_snapshot_id=snap1.id,
            current_snapshot_id=snap2.id,
            change_type="new",
            asset_type="subdomain",
        )
        session.add(change)
        session.commit()
        notif = ChangeNotification(
            asset_change_id=change.id,
            notification_type="webhook",
            recipient="https://hooks.example.com/abc",
        )
        session.add(notif)
        session.commit()
        assert "webhook" in repr(notif)


class TestWebsiteSnapshot:
    """Tests for the WebsiteSnapshot model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        ws = WebsiteSnapshot(
            subdomain_id=sub.id,
            http_status=200,
            content_hash="a" * 64,
            screenshot_path="/screenshots/example.png",
            crawl_depth=3,
        )
        session.add(ws)
        session.commit()

        assert ws.id is not None
        assert ws.http_status == 200
        assert ws.crawl_depth == 3

    def test_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        ws = WebsiteSnapshot(subdomain_id=sub.id, http_status=301)
        session.add(ws)
        session.commit()

        assert len(sub.website_snapshots) == 1
        assert ws.subdomain.subdomain == "api.example.com"

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        ws = WebsiteSnapshot(subdomain_id=sub.id, http_status=404)
        session.add(ws)
        session.commit()
        assert "404" in repr(ws)


# ---------------------------------------------------------------------------
# Group 5: Integration & System Models
# ---------------------------------------------------------------------------


class TestScannerIntegration:
    """Tests for the ScannerIntegration model."""

    def test_creation(self, session: Session) -> None:
        scanner = ScannerIntegration(
            name="Nmap",
            api_endpoint="unix:///var/run/nmap.sock",
            status="active",
        )
        session.add(scanner)
        session.commit()

        assert scanner.id is not None
        assert scanner.status == "active"

    def test_defaults(self, session: Session) -> None:
        scanner = ScannerIntegration(name="Nuclei")
        session.add(scanner)
        session.commit()

        assert scanner.status == "active"
        assert scanner.api_endpoint is None
        assert scanner.error_message is None

    def test_unique_name(self, session: Session) -> None:
        s1 = ScannerIntegration(name="Burp")
        session.add(s1)
        session.commit()

        s2 = ScannerIntegration(name="Burp")
        session.add(s2)
        with pytest.raises(Exception):
            session.commit()

    def test_repr(self, session: Session) -> None:
        scanner = ScannerIntegration(name="Trivy", status="inactive")
        session.add(scanner)
        session.commit()
        assert "Trivy" in repr(scanner)


class TestScanRunnerMetadata:
    """Tests for the ScanRunnerMetadata model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        scanner = ScannerIntegration(name="Nmap")
        session.add(scanner)
        session.commit()

        meta = ScanRunnerMetadata(
            scan_run_id=scan.id,
            scanner_integration_id=scanner.id,
            scanner_name="Nmap",
            status="completed",
            raw_results_file="/results/nmap_output.xml",
        )
        session.add(meta)
        session.commit()

        assert meta.id is not None
        assert meta.status == "completed"

    def test_relationships(self, session: Session) -> None:
        scan = _create_scan_run(session)
        scanner = ScannerIntegration(name="Nuclei")
        session.add(scanner)
        session.commit()

        meta = ScanRunnerMetadata(
            scan_run_id=scan.id,
            scanner_integration_id=scanner.id,
            scanner_name="Nuclei",
        )
        session.add(meta)
        session.commit()

        assert meta.scan_run.domain == "example.com"
        assert meta.scanner_integration.name == "Nuclei"
        assert len(scan.scanner_metadata) == 1

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        scanner = ScannerIntegration(name="TestScanner")
        session.add(scanner)
        session.commit()
        meta = ScanRunnerMetadata(
            scan_run_id=scan.id,
            scanner_integration_id=scanner.id,
            scanner_name="TestScanner",
        )
        session.add(meta)
        session.commit()
        assert "TestScanner" in repr(meta)


class TestAPIKey:
    """Tests for the APIKey model."""

    def test_creation(self, session: Session) -> None:
        key = APIKey(
            user_identifier="user@example.com",
            key_hash="$2b$12$abcdefghijklmnopqrstuv",
            name="Production Key",
        )
        session.add(key)
        session.commit()

        assert key.id is not None
        assert key.is_active is True
        assert key.expires_at is None
        assert key.last_used is None

    def test_repr(self, session: Session) -> None:
        key = APIKey(
            user_identifier="admin",
            key_hash="hash123",
            name="Test Key",
        )
        session.add(key)
        session.commit()
        assert "Test Key" in repr(key)


class TestSavedReport:
    """Tests for the SavedReport model."""

    def test_creation(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = SavedReport(
            scan_run_id=scan.id,
            report_type="executive_summary",
            format="pdf",
            file_path="/reports/exec_summary.pdf",
            generated_by="admin@technieum.io",
        )
        session.add(report)
        session.commit()

        assert report.id is not None
        assert report.format == "pdf"

    def test_relationship(self, session: Session) -> None:
        scan = _create_scan_run(session)
        r1 = SavedReport(
            scan_run_id=scan.id,
            report_type="detailed",
            format="html",
            file_path="/reports/detailed.html",
        )
        r2 = SavedReport(
            scan_run_id=scan.id,
            report_type="compliance",
            format="json",
            file_path="/reports/compliance.json",
        )
        session.add_all([r1, r2])
        session.commit()

        assert len(scan.saved_reports) == 2

    def test_repr(self, session: Session) -> None:
        scan = _create_scan_run(session)
        report = SavedReport(
            scan_run_id=scan.id,
            report_type="vuln_list",
            format="csv",
            file_path="/reports/vulns.csv",
        )
        session.add(report)
        session.commit()
        assert "csv" in repr(report)


class TestScheduledScan:
    """Tests for the ScheduledScan model."""

    def test_creation(self, session: Session) -> None:
        sched = ScheduledScan(
            domain="example.com",
            scan_type="quick",
            frequency="weekly",
            created_by="admin@technieum.io",
        )
        session.add(sched)
        session.commit()

        assert sched.id is not None
        assert sched.is_active is True
        assert sched.frequency == "weekly"

    def test_defaults(self, session: Session) -> None:
        sched = ScheduledScan(
            domain="test.org", frequency="daily"
        )
        session.add(sched)
        session.commit()

        assert sched.scan_type == "full"
        assert sched.is_active is True
        assert sched.next_run is None

    def test_repr(self, session: Session) -> None:
        sched = ScheduledScan(
            domain="corp.example.com", frequency="monthly"
        )
        session.add(sched)
        session.commit()
        assert "corp.example.com" in repr(sched)


class TestKnownVulnerability:
    """Tests for the KnownVulnerability model."""

    def test_creation(self, session: Session) -> None:
        tech = Technology(
            name="Apache", category="web_server", type="software"
        )
        session.add(tech)
        session.commit()

        kv = KnownVulnerability(
            technology_id=tech.id,
            cve_id="CVE-2021-41773",
            vuln_name="Apache Path Traversal",
            severity=95,
            advisory_url="https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            affected_versions="2.4.49",
            fixed_version="2.4.51",
        )
        session.add(kv)
        session.commit()

        assert kv.id is not None
        assert kv.severity == 95

    def test_technology_relationship(self, session: Session) -> None:
        tech = Technology(
            name="OpenSSL", category="library", type="software"
        )
        session.add(tech)
        session.commit()

        kv1 = KnownVulnerability(
            technology_id=tech.id,
            cve_id="CVE-2014-0160",
            vuln_name="Heartbleed",
            severity=100,
        )
        kv2 = KnownVulnerability(
            technology_id=tech.id,
            cve_id="CVE-2022-0778",
            vuln_name="Infinite Loop",
            severity=75,
        )
        session.add_all([kv1, kv2])
        session.commit()

        assert len(tech.known_vulnerabilities) == 2
        assert kv1.technology.name == "OpenSSL"

    def test_repr(self, session: Session) -> None:
        tech = Technology(
            name="Nginx", category="web_server", type="software"
        )
        session.add(tech)
        session.commit()
        kv = KnownVulnerability(
            technology_id=tech.id,
            cve_id="CVE-2023-1234",
            vuln_name="Test Vuln",
        )
        session.add(kv)
        session.commit()
        assert "CVE-2023-1234" in repr(kv)


# ---------------------------------------------------------------------------
# Cross-cutting tests
# ---------------------------------------------------------------------------


class TestTableCreation:
    """Verify all 25 tables are created."""

    def test_all_tables_exist(self, engine) -> None:
        inspector = inspect(engine)
        table_names = set(inspector.get_table_names())

        expected = {
            "scan_runs",
            "subdomains",
            "port_scans",
            "vulnerabilities",
            "http_headers",
            "technologies",
            "domain_technologies",
            "vulnerability_metadata",
            "dns_records",
            "isp_locations",
            "threat_intel_data",
            "compliance_reports",
            "compliance_findings",
            "risk_scores",
            "audit_logs",
            "asset_snapshots",
            "asset_changes",
            "change_notifications",
            "website_snapshots",
            "scanner_integrations",
            "scan_runner_metadata",
            "api_keys",
            "saved_reports",
            "scheduled_scans",
            "known_vulnerabilities",
        }
        assert expected.issubset(table_names), (
            f"Missing tables: {expected - table_names}"
        )

    def test_table_count(self, engine) -> None:
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        assert len(tables) >= 25  # 25 base + supplementary models


class TestCascadeDelete:
    """Verify cascade deletes propagate correctly."""

    def test_delete_scan_cascades_to_subdomains(
        self, session: Session
    ) -> None:
        scan = _create_scan_run(session)
        sub = Subdomain(scan_run_id=scan.id, subdomain="del.example.com")
        session.add(sub)
        session.commit()

        session.delete(scan)
        session.commit()

        remaining = session.query(Subdomain).all()
        assert len(remaining) == 0

    def test_delete_scan_cascades_to_vulnerabilities(
        self, session: Session
    ) -> None:
        scan = _create_scan_run(session)
        vuln = Vulnerability(
            scan_run_id=scan.id, vuln_type="test", title="Test Vuln"
        )
        session.add(vuln)
        session.commit()

        session.delete(scan)
        session.commit()

        remaining = session.query(Vulnerability).all()
        assert len(remaining) == 0

    def test_delete_subdomain_cascades_to_port_scans(
        self, session: Session
    ) -> None:
        scan = _create_scan_run(session)
        sub = _create_subdomain(session, scan)
        port = PortScan(subdomain_id=sub.id, port=8080, state="open")
        session.add(port)
        session.commit()

        session.delete(sub)
        session.commit()

        remaining = session.query(PortScan).all()
        assert len(remaining) == 0


class TestFullScanHierarchy:
    """End-to-end test building a full scan data tree."""

    def test_full_hierarchy(self, session: Session) -> None:
        # Create scan
        scan = ScanRun(domain="fulltest.com", scan_type="full")
        session.add(scan)
        session.commit()

        # Subdomain
        sub = Subdomain(
            scan_run_id=scan.id,
            subdomain="www.fulltest.com",
            is_alive=True,
        )
        session.add(sub)
        session.commit()

        # Port
        port = PortScan(
            subdomain_id=sub.id, port=443, state="open", service="HTTPS"
        )
        session.add(port)
        session.commit()

        # Vulnerability linked to subdomain and port
        vuln = Vulnerability(
            scan_run_id=scan.id,
            subdomain_id=sub.id,
            port_scan_id=port.id,
            vuln_type="weak_cipher",
            title="TLS 1.0 Enabled",
            severity=45,
        )
        session.add(vuln)
        session.commit()

        # Metadata for vulnerability
        meta = VulnerabilityMetadata(
            vulnerability_id=vuln.id,
            cve_id="CVE-2011-3389",
            cvss_v31_score=3.7,
            source="testssl",
        )
        session.add(meta)
        session.commit()

        # HTTP header
        header = HTTPHeader(
            subdomain_id=sub.id,
            header_name="Server",
            header_value="Apache/2.4.41",
        )
        session.add(header)
        session.commit()

        # DNS record
        dns = DNSRecord(
            scan_run_id=scan.id,
            domain="fulltest.com",
            record_type="A",
            value="10.0.0.1",
        )
        session.add(dns)
        session.commit()

        # Technology
        tech = Technology(
            name="Apache HTTP", category="web_server", type="software"
        )
        session.add(tech)
        session.commit()

        dt = DomainTechnology(
            scan_run_id=scan.id, technology_id=tech.id, version="2.4.41"
        )
        session.add(dt)
        session.commit()

        # Verify hierarchy navigation
        assert len(scan.subdomains) == 1
        assert len(scan.vulnerabilities) == 1
        assert len(scan.dns_records) == 1
        assert len(scan.domain_technologies) == 1
        assert scan.subdomains[0].port_scans[0].port == 443
        assert scan.vulnerabilities[0].vuln_metadata[0].cve_id == "CVE-2011-3389"
        assert scan.subdomains[0].http_headers[0].header_name == "Server"
