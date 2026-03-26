"""
Comprehensive API endpoint tests for ReconX Enterprise v2.0.
Tests all routes with authentication, pagination, filtering, and error handling.

NOTE: conftest.py patches backend.db.database.SessionLocal to use test_api.db
      so the auth middleware (which calls SessionLocal() directly) uses the same
      DB as the fixtures.
"""
import pytest
import hashlib
from fastapi.testclient import TestClient
from datetime import datetime, timezone, timedelta

# conftest.py already patched database.SessionLocal before this import
import backend.db.database as db_module
from backend.api.server import app
from backend.db.database import get_db
from backend.db.base import Base
from backend.db.models import ScanRun, APIToken, Vulnerability, Subdomain, ScanProgress

# Re-use the same engine/SessionLocal that conftest patched in
_TestingSessionLocal = db_module.SessionLocal


def override_get_db():
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="function", autouse=True)
def _clean_tables():
    """Wipe all rows between tests for isolation."""
    yield
    # teardown: delete all rows in reverse dependency order
    with db_module.engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())


@pytest.fixture(scope="function")
def db_session():
    """Provide a live DB session; tables created by conftest."""
    db = _TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def test_api_key(db_session):
    """Create a test API token."""
    key_value = "a" * 64  # 64 alphanumeric chars
    key_hash = hashlib.sha256(key_value.encode()).hexdigest()
    token = APIToken(
        token_hash=key_hash,
        user_name="test_user",
        token_type="bearer",
        is_active=True,
        expires_at=datetime.utcnow() + timedelta(days=30),  # naive UTC for SQLite
    )
    db_session.add(token)
    db_session.commit()
    return key_value


@pytest.fixture
def test_scan(db_session):
    """Create a test scan run."""
    scan = ScanRun(
        domain="example.com",
        scan_type="full",
        status="pending",
        phase=1,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


@pytest.fixture
def test_progress(db_session, test_scan):
    """Create test scan progress."""
    progress = ScanProgress(
        scan_run_id=test_scan.id,
        current_phase=1,
        progress_percentage=25,
        status="running",
        subdomains_found=3,
        vulnerabilities_found=1,
    )
    db_session.add(progress)
    db_session.commit()
    db_session.refresh(progress)
    return progress


@pytest.fixture
def test_asset(db_session, test_scan):
    """Create a test subdomain asset."""
    subdomain = Subdomain(
        subdomain="www.example.com",
        scan_run_id=test_scan.id,
        is_alive=True,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db_session.add(subdomain)
    db_session.commit()
    db_session.refresh(subdomain)
    return subdomain


@pytest.fixture
def test_vulnerability(db_session, test_scan, test_asset):
    """Create a test vulnerability."""
    vuln = Vulnerability(
        scan_run_id=test_scan.id,
        subdomain_id=test_asset.id,
        title="SQL Injection",
        vuln_type="injection",
        severity=90,
        description="SQL injection found",
        discovered_at=datetime.now(timezone.utc),
    )
    db_session.add(vuln)
    db_session.commit()
    db_session.refresh(vuln)
    return vuln


# ============================================================================
# Authentication tests
# ============================================================================

class TestAuthentication:
    def test_missing_api_key(self):
        """Request without API key is rejected."""
        response = client.get("/api/v1/scans/")
        assert response.status_code in [401, 403]
        body = response.json()
        assert "detail" in body

    def test_invalid_api_key(self):
        """Request with invalid API key is rejected."""
        response = client.get("/api/v1/scans/", headers={"X-API-Key": "wrong" * 10})
        assert response.status_code in [401, 403]

    def test_health_is_exempt(self):
        """Health endpoint does not require auth."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_version_is_exempt(self):
        """Version endpoint does not require auth."""
        response = client.get("/version")
        assert response.status_code == 200


# ============================================================================
# Scan endpoint tests
# ============================================================================

class TestScanEndpoints:
    def test_list_scans(self, test_api_key, test_scan):
        response = client.get("/api/v1/scans/?page=1&per_page=10",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data
        assert len(data["items"]) >= 1

    def test_create_scan(self, test_api_key):
        response = client.post(
            "/api/v1/scans/",
            json={"domain": "test.com", "scan_type": "quick"},
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code in [200, 201]
        data = response.json()
        assert "id" in data

    def test_create_scan_invalid_domain(self, test_api_key):
        response = client.post(
            "/api/v1/scans/",
            json={"domain": "invalid domain!", "scan_type": "full"},
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 422

    def test_get_scan(self, test_api_key, test_scan):
        response = client.get(f"/api/v1/scans/{test_scan.id}",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_scan.id

    def test_get_nonexistent_scan(self, test_api_key):
        response = client.get("/api/v1/scans/99999",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 404

    def test_get_scan_progress(self, test_api_key, test_progress):
        response = client.get(f"/api/v1/scans/{test_progress.scan_run_id}/progress",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "phase" in data
        assert "percentage" in data

    def test_start_scan(self, test_api_key, test_scan):
        response = client.post(f"/api/v1/scans/{test_scan.id}/start",
                               headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_stop_scan(self, test_api_key, test_scan):
        response = client.post(f"/api/v1/scans/{test_scan.id}/stop",
                               headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_pagination(self, test_api_key):
        response = client.get("/api/v1/scans/?page=1&per_page=5",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["per_page"] == 5


# ============================================================================
# Findings endpoint tests
# ============================================================================

class TestFindingsEndpoints:
    def test_list_findings(self, test_api_key, test_vulnerability):
        response = client.get("/api/v1/findings/?page=1&per_page=20",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_filter_by_severity(self, test_api_key, test_vulnerability):
        response = client.get("/api/v1/findings/?severity_min=80",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["severity"] >= 80

    def test_findings_by_severity(self, test_api_key, test_vulnerability):
        response = client.get("/api/v1/findings/by-severity",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data
        assert "high" in data

    def test_findings_by_type(self, test_api_key, test_vulnerability):
        response = client.get("/api/v1/findings/by-type",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_get_finding(self, test_api_key, test_vulnerability):
        response = client.get(f"/api/v1/findings/{test_vulnerability.id}",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_vulnerability.id

    def test_update_finding(self, test_api_key, test_vulnerability):
        response = client.patch(
            f"/api/v1/findings/{test_vulnerability.id}",
            json={"severity": 95},
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == 95

    def test_remediate_finding(self, test_api_key, test_vulnerability):
        response = client.post(f"/api/v1/findings/{test_vulnerability.id}/remediate",
                               headers={"X-API-Key": test_api_key})
        assert response.status_code == 200


# ============================================================================
# Assets endpoint tests
# ============================================================================

class TestAssetsEndpoints:
    def test_list_assets(self, test_api_key, test_asset):
        response = client.get("/api/v1/assets/?page=1&per_page=20",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_search_assets(self, test_api_key, test_asset):
        response = client.get("/api/v1/assets/search?q=example",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_high_risk_assets(self, test_api_key):
        response = client.get("/api/v1/assets/high-risk?min_vulns=1",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_asset_timeline(self, test_api_key, test_asset):
        response = client.get(f"/api/v1/assets/{test_asset.id}/timeline",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "events" in data

    def test_get_asset(self, test_api_key, test_asset):
        response = client.get(f"/api/v1/assets/{test_asset.id}",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_get_nonexistent_asset(self, test_api_key):
        response = client.get("/api/v1/assets/99999",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 404


# ============================================================================
# Reports endpoint tests
# ============================================================================

class TestReportsEndpoints:
    def test_list_reports(self, test_api_key):
        response = client.get("/api/v1/reports/?page=1&per_page=20",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_generate_report(self, test_api_key, test_scan):
        response = client.post(
            f"/api/v1/reports/?scan_run_id={test_scan.id}&report_type=technical",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200

    def test_list_templates(self, test_api_key):
        response = client.get("/api/v1/reports/templates",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "templates" in data
        assert "technical" in data["templates"]


# ============================================================================
# Intelligence endpoint tests
# ============================================================================

class TestIntelligenceEndpoints:
    def test_threat_feed(self, test_api_key):
        response = client.get("/api/v1/intel/threat-feed?page=1&per_page=20",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_data_leaks(self, test_api_key):
        response = client.get("/api/v1/intel/data-leaks?page=1&per_page=20",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200

    def test_malware_lookup(self, test_api_key):
        response = client.get("/api/v1/intel/malware/test_hash_123",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "found" in data

    def test_ip_reputation(self, test_api_key):
        response = client.get("/api/v1/intel/ip-reputation/1.2.3.4",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "ip" in data

    def test_domain_reputation(self, test_api_key):
        response = client.get("/api/v1/intel/domain-reputation/example.com",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200


# ============================================================================
# Webhooks endpoint tests
# ============================================================================

class TestWebhooksEndpoints:
    def test_list_webhooks_empty(self, test_api_key):
        response = client.get("/api/v1/webhooks/",
                              headers={"X-API-Key": test_api_key})
        assert response.status_code == 200
        data = response.json()
        assert "total" in data

    def test_create_and_list_webhook(self, test_api_key):
        # Create
        create_resp = client.post(
            "/api/v1/webhooks/",
            json={"url": "https://example.com/webhook", "events": ["scan.completed"]},
            headers={"X-API-Key": test_api_key},
        )
        assert create_resp.status_code == 200
        data = create_resp.json()
        assert "id" in data
        assert data["active"] is True

    def test_delete_nonexistent_webhook(self, test_api_key):
        response = client.delete("/api/v1/webhooks/99999",
                                 headers={"X-API-Key": test_api_key})
        assert response.status_code == 404


# ============================================================================
# Rate limiting tests
# ============================================================================

class TestRateLimiting:
    def test_rate_limit_headers(self, test_api_key):
        response = client.get("/api/v1/scans/", headers={"X-API-Key": test_api_key})
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
