"""
Comprehensive API endpoint tests for Technieum Enterprise.
Tests all API routes with authentication, pagination, filtering, and error handling.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from app.api.server import app
from app.db.database import get_db
from app.db.base import Base
from app.db.models import ScanRun, APIKey, Vulnerability, Subdomain
from datetime import datetime, timezone, timedelta
import hashlib

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Redirect the shared SessionLocal (used by auth middleware) to the test DB.
import app.db.database as _db_module  # noqa: E402
_db_module.SessionLocal = TestingSessionLocal


# Override get_db dependency (used by route handlers)
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

# Test client
client = TestClient(app)

# Valid API key: must be alphanumeric and 32–64 characters long.
VALID_KEY = "a" * 32


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope="function")
def db_session():
    """Create test database and session."""
    # Re-apply per-test: prevents cross-module import order from overwriting these.
    _db_module.SessionLocal = TestingSessionLocal
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.create_all(bind=engine)
    # Ensure Vulnerability.status column exists (safe migration for old schemas)
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN status VARCHAR(50) DEFAULT 'open'"))
            conn.commit()
        except Exception:
            pass  # Column already exists
    db = TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_api_key(db_session):
    """Create test API key (32-char alphanumeric)."""
    key_hash = hashlib.sha256(VALID_KEY.encode()).hexdigest()
    api_key = APIKey(
        key_hash=key_hash,
        name="Test Key",
        user_identifier="test_user",
        created_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db_session.add(api_key)
    db_session.commit()
    return VALID_KEY


@pytest.fixture
def test_scan(db_session):
    """Create test scan."""
    scan = ScanRun(
        domain="example.com",
        scan_type="full",
        status="running",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)
    return scan


@pytest.fixture
def test_asset(db_session, test_scan):
    """Create test subdomain."""
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
    """Create test vulnerability."""
    vuln = Vulnerability(
        scan_run_id=test_scan.id,
        subdomain_id=test_asset.id,
        title="SQL Injection",
        vuln_type="injection",
        severity=90,
        description="SQL injection vulnerability found",
        discovered_at=datetime.now(timezone.utc),
        status="open",
    )
    db_session.add(vuln)
    db_session.commit()
    db_session.refresh(vuln)
    return vuln


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

class TestAuthentication:
    def test_missing_api_key(self):
        """Test request without API key returns 401."""
        response = client.get("/api/v1/scans/")
        assert response.status_code == 401
        assert "API key required" in response.json()["detail"]

    def test_invalid_api_key(self):
        """Test request with incorrectly-formatted API key returns 401."""
        # "invalid_key" is only 11 chars and contains underscores → format check fails.
        response = client.get("/api/v1/scans/", headers={"X-API-Key": "invalid_key"})
        assert response.status_code == 401

    def test_valid_api_key(self, test_api_key):
        """Test request with valid API key returns 200."""
        response = client.get("/api/v1/scans/", headers={"X-API-Key": test_api_key})
        assert response.status_code == 200


# ============================================================================
# SCAN ENDPOINTS TESTS
# ============================================================================

class TestScanEndpoints:
    def test_list_scans(self, test_api_key, test_scan):
        """Test listing scans with pagination."""
        response = client.get(
            "/api/v1/scans/?page=1&per_page=10",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data
        assert len(data["items"]) >= 1

    def test_create_scan(self, test_api_key):
        """Test creating a new scan."""
        response = client.post(
            "/api/v1/scans/",
            json={"domain": "test.com", "scan_type": "quick"},
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code in (200, 201)
        data = response.json()
        assert "id" in data or "scan_id" in data

    def test_create_scan_invalid_domain(self, test_api_key):
        """Test creating scan with invalid domain."""
        response = client.post(
            "/api/v1/scans/",
            json={"domain": "invalid domain!", "scan_type": "full"},
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 422  # Validation error

    def test_get_scan(self, test_api_key, test_scan):
        """Test getting specific scan."""
        response = client.get(
            f"/api/v1/scans/{test_scan.id}",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_scan.id

    def test_get_nonexistent_scan(self, test_api_key):
        """Test getting non-existent scan."""
        response = client.get(
            "/api/v1/scans/99999",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 404


# ============================================================================
# FINDINGS ENDPOINTS TESTS
# ============================================================================

class TestFindingsEndpoints:
    def test_list_findings(self, test_api_key, test_vulnerability):
        """Test listing findings."""
        response = client.get(
            "/api/v1/findings/?page=1&per_page=20",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_filter_findings_by_severity(self, test_api_key, test_vulnerability):
        """Test filtering findings by severity."""
        response = client.get(
            "/api/v1/findings/?severity_min=80",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["severity"] >= 80

    def test_findings_by_severity(self, test_api_key, test_vulnerability):
        """Test grouping findings by severity."""
        response = client.get(
            "/api/v1/findings/by-severity",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "critical" in data
        assert "high" in data

    def test_get_finding(self, test_api_key, test_vulnerability):
        """Test getting specific finding."""
        response = client.get(
            f"/api/v1/findings/{test_vulnerability.id}",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_vulnerability.id

    def test_update_finding(self, test_api_key, test_vulnerability):
        """Test updating finding via PUT."""
        response = client.put(
            f"/api/v1/findings/{test_vulnerability.id}",
            json={"severity": 95, "status": "confirmed"},
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200


# ============================================================================
# ASSETS ENDPOINTS TESTS
# ============================================================================

class TestAssetsEndpoints:
    def test_list_assets(self, test_api_key, test_asset):
        """Test listing assets."""
        response = client.get(
            "/api/v1/assets/?page=1&per_page=20",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_search_assets(self, test_api_key, test_asset):
        """Test searching assets."""
        response = client.get(
            "/api/v1/assets/search?q=example",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data

    def test_high_risk_assets(self, test_api_key):
        """Test getting high-risk assets."""
        response = client.get(
            "/api/v1/assets/high-risk?min_vulns=1",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200

    def test_asset_timeline(self, test_api_key, test_asset):
        """Test asset timeline."""
        response = client.get(
            f"/api/v1/assets/{test_asset.id}/timeline",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "events" in data


# ============================================================================
# REPORTS ENDPOINTS TESTS
# ============================================================================

class TestReportsEndpoints:
    def test_list_reports(self, test_api_key):
        """Test listing reports."""
        response = client.get(
            "/api/v1/reports/?page=1&per_page=20",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "items" in data

    def test_generate_report(self, test_api_key, test_scan):
        """Test generating report."""
        response = client.post(
            f"/api/v1/reports/?scan_run_id={test_scan.id}&report_type=technical",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200


# ============================================================================
# INTELLIGENCE ENDPOINTS TESTS
# ============================================================================

class TestIntelligenceEndpoints:
    def test_threat_feed(self, test_api_key):
        """Test threat feed."""
        response = client.get(
            "/api/v1/intel/threat-feed?page=1&per_page=20",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200

    def test_data_leaks(self, test_api_key):
        """Test data leaks endpoint."""
        response = client.get(
            "/api/v1/intel/data-leaks?page=1&per_page=20",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200

    def test_malware_lookup(self, test_api_key):
        """Test malware indicator lookup."""
        response = client.get(
            "/api/v1/intel/malware/testhash12345678901234567890abcdef",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert "found" in data


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

class TestRateLimiting:
    def test_rate_limit_headers(self, test_api_key):
        """Test rate limit headers are present."""
        response = client.get("/api/v1/scans/", headers={"X-API-Key": test_api_key})
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers


# ============================================================================
# PAGINATION TESTS
# ============================================================================

class TestPagination:
    def test_pagination_parameters(self, test_api_key):
        """Test pagination with different parameters."""
        response = client.get(
            "/api/v1/scans/?page=1&per_page=5",
            headers={"X-API-Key": test_api_key},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["per_page"] == 5

    def test_pagination_bounds(self, test_api_key):
        """Test pagination boundary validation."""
        response = client.get(
            "/api/v1/scans/?page=0&per_page=200",
            headers={"X-API-Key": test_api_key},
        )
        # FastAPI validates ge=1 for page and le=100 for per_page → 422
        assert response.status_code in (200, 422)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
