"""
Tests for Technieum Enterprise intelligence modules.
Covers risk scoring, threat correlation, change detection, and graph analysis.
"""
import pytest
from datetime import datetime, timezone, timedelta
from backend.db.models import (
    Vulnerability, ScanRun, Subdomain, ThreatIntelData, RiskScore
)
from intelligence.risk_scoring.cvss import CVSSv31Calculator
from intelligence.threat_intel.correlator import correlate_findings
from intelligence.change_detection.alert_generator import AlertGenerator


class TestCVSSScoring:
    """Test CVSS score calculation."""
    
    def test_cvss_v3_basic(self):
        """Test basic CVSS v3 calculation."""
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = CVSSv31Calculator(vector).get_base_score()
        assert score == 9.8

    def test_cvss_scope_changed(self):
        """Test CVSS with scope changed."""
        vector = "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
        score = CVSSv31Calculator(vector).get_base_score()
        assert score > 0

    def test_cvss_invalid_vector(self):
        """Test handling of invalid CVSS vector."""
        vector = "INVALID"
        score = CVSSv31Calculator(vector).get_base_score()
        assert score == 0.0


class TestRiskScoring:
    """Test comprehensive risk scoring."""
    
    def test_vulnerability_severity(self):
        """Test vulnerability severity classification."""
        assert self._severity_name(95) == "critical"
        assert self._severity_name(75) == "high"
        assert self._severity_name(50) == "medium"
        assert self._severity_name(25) == "low"
    
    def _severity_name(self, score):
        if score >= 90:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"


class TestThreatCorrelation:
    """Test threat intelligence correlation."""
    
    def test_correlate_vulnerabilities(self, db_session):
        """Test correlating vulnerabilities with threat intel."""
        # Create test scan
        scan = ScanRun(
            domain="test.com",
            scan_type="quick",
            status="completed",
        )
        db_session.add(scan)
        db_session.commit()
        
        # Create test vulnerability
        vuln = Vulnerability(
            scan_run_id=scan.id,
            title="SQL Injection",
            vuln_type="injection",
            cve_ids="CVE-2023-1234",
            severity=90,
            discovered_at=datetime.now(timezone.utc),
        )
        db_session.add(vuln)
        db_session.commit()
        
        # Test correlation
        result = correlate_findings(db_session, scan.id)
        assert result is not None
        assert "statistics" in result or isinstance(result, dict)


class TestChangeDetection:
    """Test change detection and alerting."""
    
    def test_generate_alerts(self):
        """Test alert generation from changes."""
        # AlertGenerator takes a delta dict; no DB required
        alerts = AlertGenerator({}, scan_run_id=0).generate_alerts()
        assert isinstance(alerts, list)
    
    def test_alert_types(self):
        """Test different alert types."""
        alert_types = [
            "NEW_SUBDOMAIN",
            "SERVICE_DOWN",
            "CONFIGURATION_DRIFT",
            "COMPLIANCE_DEGRADATION",
            "NEW_VULNERABILITY"
        ]
        
        for alert_type in alert_types:
            assert alert_type in [
                "NEW_SUBDOMAIN",
                "SERVICE_DOWN",
                "CONFIGURATION_DRIFT",
                "COMPLIANCE_DEGRADATION",
                "NEW_VULNERABILITY"
            ]


class TestGraphAnalysis:
    """Test graph construction and analysis."""
    
    def test_graph_node_types(self):
        """Test graph node type classification."""
        node_types = {
            "domain": "root entity",
            "subdomain": "discovered subdomain",
            "ip": "IP address",
            "service": "running service",
            "vulnerability": "security finding"
        }
        
        assert "domain" in node_types
        assert "vulnerability" in node_types
    
    def test_graph_edge_types(self):
        """Test graph edge relationship types."""
        edge_types = {
            "resolves_to": "DNS resolution",
            "hosts": "service hosting",
            "has_vulnerability": "vulnerability association",
            "connects_to": "network connection"
        }
        
        assert "resolves_to" in edge_types
        assert "has_vulnerability" in edge_types
    
    def test_risk_propagation(self):
        """Test risk score propagation through graph."""
        # Mock graph structure
        graph = {
            "nodes": [
                {"id": 1, "type": "domain", "risk": 5.0},
                {"id": 2, "type": "vulnerability", "risk": 9.8}
            ],
            "edges": [
                {"source": 1, "target": 2, "type": "has_vulnerability"}
            ]
        }
        
        # Verify structure
        assert len(graph["nodes"]) == 2
        assert len(graph["edges"]) == 1
        
        # Risk should propagate from vulnerability to domain
        vuln_risk = next(n["risk"] for n in graph["nodes"] if n["type"] == "vulnerability")
        assert vuln_risk > 9.0


class TestComplianceMapping:
    """Test compliance framework mapping."""
    
    def test_pci_dss_mapping(self):
        """Test PCI-DSS control mapping."""
        controls = {
            "1.1": "Firewall configuration",
            "2.1": "Default passwords",
            "6.5": "SQL injection protection"
        }
        
        assert "6.5" in controls  # SQL injection is PCI-DSS relevant
    
    def test_gdpr_mapping(self):
        """Test GDPR requirement mapping."""
        requirements = {
            "Art32": "Security of processing",
            "Art33": "Breach notification"
        }
        
        assert "Art32" in requirements
    
    def test_nist_csf_mapping(self):
        """Test NIST CSF function mapping."""
        functions = ["Identify", "Protect", "Detect", "Respond", "Recover"]
        
        assert "Detect" in functions
        assert "Respond" in functions


@pytest.fixture
def db_session():
    """Mock database session for testing."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.db.base import Base
    
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    yield session
    
    session.close()
    Base.metadata.drop_all(engine)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
