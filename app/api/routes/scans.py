"""Scan management API routes.

Supports two request styles for scan creation:
  - JSON body: {"domain": "example.com", "scan_type": "full"}  (canonical)
  - Query params: ?target=example.com&phases=1,2,3,4           (legacy UI compat)
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone

from app.db.database import get_db
from app.db.models import ScanRun, ScanProgress, ScanJob
from app.api.models.scan import ScanCreateRequest, ScanUpdateRequest, ScanResponse, ScanListResponse
from app.api.models.common import StatusResponse

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _phases_to_scan_type(phases_str: Optional[str]) -> str:
    """Map legacy ?phases=1,2,3,4 query parameter to a scan_type string."""
    if not phases_str:
        return "full"
    try:
        phases = [int(p.strip()) for p in phases_str.split(",") if p.strip()]
    except ValueError:
        return "full"
    if phases == [0]:
        return "quick"
    if sorted(phases) == list(range(0, 5)):
        return "deep"
    return "full"


def _enqueue(scan: ScanRun, db: Session) -> None:
    """Create ScanProgress + ScanJob in the same transaction as the caller."""
    progress = ScanProgress(scan_run_id=scan.id, status="queued")
    db.add(progress)
    job = ScanJob(
        scan_run_id=scan.id,
        status="queued",
        queued_at=datetime.now(timezone.utc),
    )
    db.add(job)


def _scan_to_dict(scan: ScanRun) -> dict:
    """Return scan data including legacy field aliases expected by the UI."""
    return {
        "id": scan.id,
        "scan_id": str(scan.id),          # legacy alias used by dashboard-v2.js
        "domain": scan.domain,
        "target": scan.domain,            # legacy alias used by dashboard-v2.js
        "scan_type": scan.scan_type,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "phase": scan.phase,
        "started_at": scan.created_at.isoformat() if scan.created_at else None,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "phases": {},   # populated below for quick compat
    }


# ---------------------------------------------------------------------------
# Collection routes
# ---------------------------------------------------------------------------

@router.get("/", summary="List all scans")
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    domain: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all scan runs. Returns both ORM schema and legacy-alias fields."""
    q = db.query(ScanRun)
    if status:
        q = q.filter(ScanRun.status == status)
    if domain:
        q = q.filter(ScanRun.domain.contains(domain))
    total = q.count()
    items_orm = q.offset((page - 1) * per_page).limit(per_page).all()
    items = [_scan_to_dict(s) for s in items_orm]
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": items,
        "scans": items,   # legacy alias used by dashboard-v2.js
    }


@router.post("/", status_code=201, summary="Create scan")
def create_scan(
    # JSON body (canonical)
    req: Optional[ScanCreateRequest] = None,
    # Query params (legacy UI compat)
    target: Optional[str] = Query(None, description="Target domain (legacy UI)"),
    phases: Optional[str] = Query(None, description="Comma-separated phases (legacy UI)"),
    test_mode: Optional[bool] = Query(False, description="Test mode flag (legacy UI)"),
    db: Session = Depends(get_db),
):
    """Create a new scan.

    Accepts either:
    - POST /scans/ with JSON body {"domain": "...", "scan_type": "..."}
    - POST /scans/?target=example.com&phases=1,2,3  (legacy dashboard format)
    """
    if req is not None:
        domain = req.domain
        scan_type = req.scan_type
    elif target:
        # Legacy query-param format
        from pydantic import ValidationError
        try:
            validated = ScanCreateRequest(domain=target, scan_type=_phases_to_scan_type(phases))
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        domain = validated.domain
        scan_type = validated.scan_type
    else:
        raise HTTPException(
            status_code=422,
            detail="Either JSON body with 'domain' or query param 'target' is required",
        )

    scan = ScanRun(domain=domain, scan_type=scan_type, status="queued")
    db.add(scan)
    db.flush()
    _enqueue(scan, db)
    db.commit()
    db.refresh(scan)
    return _scan_to_dict(scan)


# ---------------------------------------------------------------------------
# Item routes
# ---------------------------------------------------------------------------

@router.get("/{scan_id}", summary="Get scan")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_dict(scan)


@router.put("/{scan_id}", summary="Update scan")
def update_scan(scan_id: int, req: ScanUpdateRequest, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if req.status:
        scan.status = req.status
    if req.scan_type:
        scan.scan_type = req.scan_type
    db.commit()
    db.refresh(scan)
    return _scan_to_dict(scan)


@router.delete("/{scan_id}", response_model=StatusResponse, summary="Delete scan")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return StatusResponse(status="deleted", message=f"Scan {scan_id} deleted")


@router.post("/{scan_id}/start", response_model=StatusResponse, summary="Start scan")
def start_scan(scan_id: int, db: Session = Depends(get_db)):
    """Enqueue a scan job. Idempotent — won't create duplicate active jobs."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Scan already running")

    active_job = (
        db.query(ScanJob)
        .filter(
            ScanJob.scan_run_id == scan_id,
            ScanJob.status.in_(["queued", "running"]),
        )
        .first()
    )
    if not active_job:
        db.add(ScanJob(
            scan_run_id=scan_id,
            status="queued",
            queued_at=datetime.now(timezone.utc),
        ))

    scan.status = "queued"
    db.commit()
    return StatusResponse(status="queued", message=f"Scan {scan_id} queued for execution")


@router.post("/{scan_id}/stop", response_model=StatusResponse, summary="Stop scan")
def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    """Stop a running scan.

    Sets the scan status to 'stopped' and marks any active ScanJob as 'stopped'
    so the worker will not continue processing it. Running worker processes will
    detect the status change on their next poll and terminate the subprocess.
    """
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.status = "stopped"

    # Mark active jobs as stopped so worker knows to abort
    active_jobs = (
        db.query(ScanJob)
        .filter(
            ScanJob.scan_run_id == scan_id,
            ScanJob.status.in_(["queued", "running"]),
        )
        .all()
    )
    for job in active_jobs:
        job.status = "stopped"

    # Update progress record if present
    progress = db.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first()
    if progress:
        progress.status = "stopped"

    db.commit()
    return StatusResponse(status="stopped", message=f"Scan {scan_id} stopped")


@router.get("/{scan_id}/progress", summary="Get scan progress")
def get_progress(scan_id: int, db: Session = Depends(get_db)):
    progress = db.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first()
    if not progress:
        raise HTTPException(status_code=404, detail="Progress not found")
    return {
        "scan_id": scan_id,
        "phase": progress.current_phase,
        "tool": progress.current_tool,
        "percentage": progress.progress_percentage,
        "status": progress.status,
        "subdomains_found": progress.subdomains_found,
        "vulnerabilities_found": progress.vulnerabilities_found,
    }


@router.get("/{scan_id}/status", summary="Get scan status (alias for progress)")
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    """Alias of /progress — UI sometimes calls /status instead."""
    return get_progress(scan_id, db)


@router.get("/{scan_id}/job", summary="Get queue job status")
def get_job(scan_id: int, db: Session = Depends(get_db)):
    job = (
        db.query(ScanJob)
        .filter(ScanJob.scan_run_id == scan_id)
        .order_by(ScanJob.id.desc())
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="No job found for this scan")
    return {
        "job_id": job.id,
        "scan_run_id": job.scan_run_id,
        "status": job.status,
        "worker_id": job.worker_id,
        "queued_at": job.queued_at.isoformat() if job.queued_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "error": job.error,
    }
