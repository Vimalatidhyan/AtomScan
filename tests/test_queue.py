"""Queue / worker integration tests.

Tests:
  - Scan lifecycle: create → queued → running → completed/failed
  - Atomic job claim: concurrent workers cannot double-claim one job
  - Worker hard-fails when harness is missing
  - Stream endpoint reads real ScanEvent rows (not synthetic data)
  - Webhook delivery (success + failure paths, HMAC signature)
"""
import hashlib
import hmac
import json
import threading
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import ScanRun, ScanJob, ScanEvent, ScanProgress, APIKey


# ---------------------------------------------------------------------------
# Test DB setup
# ---------------------------------------------------------------------------

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_queue.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

import app.db.database as _db_module  # noqa: E402
_db_module.SessionLocal = Session

import app.workers.worker as _worker  # noqa: E402
_worker._engine = engine
_worker._Session = Session

from app.api.server import app  # noqa: E402
from app.db.database import get_db  # noqa: E402

VALID_KEY = "a" * 32


def override_get_db():
    db = Session()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_db():
    # Re-apply per-test: prevents cross-module import order from overwriting these.
    _db_module.SessionLocal = Session
    app.dependency_overrides[get_db] = override_get_db
    _worker._engine = engine
    _worker._Session = Session
    Base.metadata.create_all(bind=engine)
    # Ensure new tables exist (test DB might predate migrations)
    with engine.begin() as conn:
        for stmt in [
            "ALTER TABLE vulnerabilities ADD COLUMN status VARCHAR(50) DEFAULT 'open'",
            """CREATE TABLE IF NOT EXISTS scan_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'queued',
                worker_id VARCHAR(100),
                queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                finished_at TIMESTAMP,
                error TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_id ON scan_jobs(status, id)",
            """CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                event_type VARCHAR(50) NOT NULL DEFAULT 'log',
                level VARCHAR(20) NOT NULL DEFAULT 'info',
                message TEXT,
                data TEXT,
                phase INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""",
        ]:
            try:
                conn.execute(text(stmt))
            except Exception:
                pass  # already exists

    # Seed API key
    db = Session()
    key_hash = hashlib.sha256(VALID_KEY.encode()).hexdigest()
    if not db.query(APIKey).filter(APIKey.key_hash == key_hash).first():
        db.add(APIKey(
            key_hash=key_hash,
            name="Test Key",
            user_identifier="test_user",
            expires_at=datetime.now(timezone.utc).replace(year=2099),
        ))
        db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# A) Queue wiring — create scan enqueues a job
# ---------------------------------------------------------------------------

class TestQueueWiring:
    def test_create_scan_enqueues_job(self):
        """POST /api/v1/scans/ must create a ScanJob with status='queued'."""
        resp = client.post(
            "/api/v1/scans/",
            json={"domain": "queue-test.example.com", "scan_type": "quick"},
            headers={"X-API-Key": VALID_KEY},
        )
        assert resp.status_code == 201, resp.text
        scan_id = resp.json()["id"]

        db = Session()
        job = db.query(ScanJob).filter(ScanJob.scan_run_id == scan_id).first()
        assert job is not None, "No ScanJob created"
        assert job.status == "queued"
        db.close()

    def test_start_scan_idempotent(self):
        """Calling /start twice must not create duplicate jobs."""
        resp = client.post(
            "/api/v1/scans/",
            json={"domain": "idempotent.example.com", "scan_type": "quick"},
            headers={"X-API-Key": VALID_KEY},
        )
        scan_id = resp.json()["id"]

        # First /start
        r1 = client.post(f"/api/v1/scans/{scan_id}/start",
                         headers={"X-API-Key": VALID_KEY})
        assert r1.status_code == 200

        # Second /start — should not add a second queued job
        r2 = client.post(f"/api/v1/scans/{scan_id}/start",
                         headers={"X-API-Key": VALID_KEY})
        assert r2.status_code == 200

        db = Session()
        jobs = db.query(ScanJob).filter(ScanJob.scan_run_id == scan_id).all()
        active = [j for j in jobs if j.status in ("queued", "running")]
        assert len(active) == 1, f"Expected 1 active job, got {len(active)}"
        db.close()

    def test_get_job_endpoint(self):
        """GET /api/v1/scans/{id}/job returns job details."""
        resp = client.post(
            "/api/v1/scans/",
            json={"domain": "jobcheck.example.com", "scan_type": "quick"},
            headers={"X-API-Key": VALID_KEY},
        )
        scan_id = resp.json()["id"]
        jr = client.get(f"/api/v1/scans/{scan_id}/job",
                        headers={"X-API-Key": VALID_KEY})
        assert jr.status_code == 200
        data = jr.json()
        assert data["status"] == "queued"
        assert data["scan_run_id"] == scan_id


# ---------------------------------------------------------------------------
# B) Worker harness validation
# ---------------------------------------------------------------------------

class TestWorkerHarness:
    def test_worker_fails_hard_when_harness_missing(self):
        """Worker must raise FileNotFoundError when run_scan.sh is absent."""
        db = Session()
        scan = ScanRun(domain="harness-test.example.com", scan_type="quick", status="queued")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_run_id=scan.id, status="queued")
        db.add(job)
        progress = ScanProgress(scan_run_id=scan.id, status="queued")
        db.add(progress)
        db.commit()
        scan_id = scan.id
        db.close()

        # Point harness to a non-existent path
        original = _worker._HARNESS
        from pathlib import Path
        _worker._HARNESS = Path("/nonexistent/run_scan.sh")
        try:
            db2 = Session()
            with pytest.raises(FileNotFoundError):
                _worker._run_scan(scan_id, db2)
            db2.close()
        finally:
            _worker._HARNESS = original

    def test_worker_processes_quick_scan(self):
        """Worker completes a quick scan using real harness (dns-only path)."""
        db = Session()
        scan = ScanRun(domain="example.com", scan_type="quick", status="queued")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_run_id=scan.id, status="queued")
        db.add(job)
        progress = ScanProgress(scan_run_id=scan.id, status="queued")
        db.add(progress)
        db.commit()
        scan_id = scan.id
        db.close()

        # Run the worker in drain mode
        n = _worker.run_once()
        assert n >= 1, f"Expected at least 1 job processed, got {n}"

        db3 = Session()
        scan_after = db3.query(ScanRun).filter(ScanRun.id == scan_id).first()
        job_after = db3.query(ScanJob).filter(ScanJob.scan_run_id == scan_id).first()
        events = db3.query(ScanEvent).filter(ScanEvent.scan_run_id == scan_id).all()
        db3.close()

        assert scan_after.status in ("completed", "failed"), \
            f"Unexpected scan status: {scan_after.status}"
        assert job_after.status in ("done", "failed"), \
            f"Unexpected job status: {job_after.status}"
        assert len(events) > 0, "Worker must write ScanEvent rows"


# ---------------------------------------------------------------------------
# C) Atomic claim — no double-claim under concurrency
# ---------------------------------------------------------------------------

class TestAtomicClaim:
    def test_no_double_claim_concurrent_workers(self):
        """Two concurrent threads must not claim the same job."""
        db = Session()
        scan = ScanRun(domain="atomic-test.example.com", scan_type="quick", status="queued")
        db.add(scan)
        db.flush()
        job = ScanJob(scan_run_id=scan.id, status="queued")
        db.add(job)
        progress = ScanProgress(scan_run_id=scan.id, status="queued")
        db.add(progress)
        db.commit()
        job_id = job.id
        db.close()

        claimed_jobs = []
        errors = []

        def try_claim():
            db2 = Session()
            try:
                # Use distinct worker IDs to tell them apart
                import uuid
                original_wid = _worker._WORKER_ID
                _worker._WORKER_ID = uuid.uuid4().hex
                job_obj = _worker._claim_job(db2)
                if job_obj is not None:
                    claimed_jobs.append(job_obj.id)
                _worker._WORKER_ID = original_wid
            except Exception as e:
                errors.append(str(e))
            finally:
                db2.close()

        t1 = threading.Thread(target=try_claim)
        t2 = threading.Thread(target=try_claim)
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert not errors, f"Claim errors: {errors}"
        assert len(claimed_jobs) <= 1, \
            f"Double-claim detected: {len(claimed_jobs)} workers claimed job {job_id}"


# ---------------------------------------------------------------------------
# D) Stream reads real ScanEvent rows
# ---------------------------------------------------------------------------

class TestStreamTelemetry:
    def test_stream_returns_db_events(self):
        """Stream endpoint must only emit ScanEvent rows from the DB."""
        db = Session()
        scan = ScanRun(domain="stream-test.example.com", scan_type="quick", status="running")
        db.add(scan)
        db.flush()
        progress = ScanProgress(scan_run_id=scan.id, status="running")
        db.add(progress)

        # Write a known ScanEvent
        ev = ScanEvent(
            scan_run_id=scan.id,
            event_type="log",
            level="info",
            message="real telemetry marker XYZ",
            created_at=datetime.now(timezone.utc),
        )
        db.add(ev)
        # Immediately complete the scan so the stream terminates
        scan.status = "completed"
        db.commit()
        scan_id = scan.id
        db.close()

        # Use TestClient with stream=True to read one chunk
        with client.stream(
            "GET",
            f"/api/v1/stream/logs/{scan_id}",
            headers={"X-API-Key": VALID_KEY},
        ) as r:
            chunks = []
            for chunk in r.iter_text():
                chunks.append(chunk)
                if len(chunks) >= 5:
                    break

        full = "".join(chunks)
        assert "real telemetry marker XYZ" in full, \
            f"Stream did not return the known event.  Got:\n{full[:500]}"
        # Must NOT contain synthetic phase strings
        assert "Prescan" not in full, "Stream contains synthetic hardcoded strings"
        assert "Discovery" not in full, "Stream contains synthetic hardcoded strings"


# ---------------------------------------------------------------------------
# G) Webhook delivery — success and failure paths
# ---------------------------------------------------------------------------

class TestWebhookDelivery:
    def test_webhook_hmac_signature(self):
        """_build_signature must produce valid HMAC-SHA256."""
        from app.api.routes.webhooks import _build_signature
        secret = "test-secret"
        body = b'{"event": "test"}'
        sig = _build_signature(secret, body)
        assert sig.startswith("sha256=")
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert sig == expected

    def test_webhook_delivery_success(self):
        """_deliver must POST payload and return True on 2xx response."""
        from app.api.routes.webhooks import _deliver, Webhook
        wh = Webhook(url="https://example.com/hook", events="test", active=True, secret="s3cr3t",
                     success_count=0, failure_count=0)
        mock_resp = MagicMock()
        mock_resp.is_success = True
        with patch("httpx.post", return_value=mock_resp) as mock_post:
            ok, err = _deliver(wh, "scan.completed", {"scan_id": 1})
        assert ok is True
        assert err == ""
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["headers"]["X-Technieum-Event"] == "scan.completed"
        # Signature header must be present
        assert "X-Technieum-Signature" in call_kwargs["headers"]
        assert call_kwargs["headers"]["X-Technieum-Signature"].startswith("sha256=")

    def test_webhook_delivery_failure(self):
        """_deliver must return False on non-2xx response."""
        from app.api.routes.webhooks import _deliver, Webhook
        import httpx as _httpx
        wh = Webhook(url="https://example.com/hook", events="test", active=True,
                     secret=None, success_count=0, failure_count=0)
        with patch("httpx.post", side_effect=_httpx.ConnectError("refused")):
            ok, err = _deliver(wh, "webhook.test", {"x": 1})
        assert ok is False
        assert "request error" in err.lower()

    def test_webhook_test_endpoint_persists_result(self):
        """POST /webhooks/{id}/test must update success_count or failure_count."""
        db = Session()
        from app.db.models import Webhook as WebhookModel
        wh = WebhookModel(
            url="https://httpbin.org/post",
            events="webhook.test",
            active=True,
            success_count=0,
            failure_count=0,
        )
        db.add(wh)
        db.commit()
        wh_id = wh.id
        db.close()

        # Mock the actual HTTP call
        mock_resp = MagicMock()
        mock_resp.is_success = True
        with patch("httpx.post", return_value=mock_resp):
            resp = client.post(
                f"/api/v1/webhooks/{wh_id}/test",
                headers={"X-API-Key": VALID_KEY},
            )
        assert resp.status_code == 200

        db2 = Session()
        wh2 = db2.query(WebhookModel).filter(WebhookModel.id == wh_id).first()
        assert wh2.success_count == 1
        assert wh2.last_triggered is not None
        db2.close()
