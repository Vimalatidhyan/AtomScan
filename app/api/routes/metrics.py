"""Observability metrics endpoint.

Returns lightweight operational counters in JSON.  No external metrics
library required — all data comes from the in-process state the app
already tracks (DB row counts, cache size, rate-limit store).
"""
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import ScanRun, Vulnerability, AssetSnapshot, APIKey
from app.api.middleware.auth import _key_cache, AUTH_CACHE_TTL

router = APIRouter()

_START_TIME = time.monotonic()


@router.get("/", summary="Operational metrics")
def get_metrics(db: Session = Depends(get_db)):
    """Return lightweight operational metrics as JSON."""
    uptime_s = round(time.monotonic() - _START_TIME)

    scan_counts: dict[str, int] = {}
    for row in db.execute(text("SELECT status, COUNT(*) FROM scan_runs GROUP BY status")):
        scan_counts[row[0]] = row[1]

    return {
        "uptime_seconds": uptime_s,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db": {
            "scans_total": db.query(ScanRun).count(),
            "scans_by_status": scan_counts,
            "vulnerabilities_total": db.query(Vulnerability).count(),
            "asset_snapshots_total": db.query(AssetSnapshot).count(),
            "api_keys_active": db.query(APIKey).filter(APIKey.is_active).count(),
        },
        "auth_cache": {
            "entries": len(_key_cache),
            "ttl_seconds": AUTH_CACHE_TTL,
        },
    }
