"""Scan management API routes."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from backend.db.database import get_db
from backend.db.models import ScanRun, ScanProgress
from backend.api.models.scan import ScanCreateRequest, ScanUpdateRequest, ScanResponse, ScanListResponse
from backend.api.models.common import StatusResponse

router = APIRouter()


@router.get("/", response_model=ScanListResponse, summary="List all scans")
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    domain: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all scan runs with optional filtering."""
    q = db.query(ScanRun)
    if status:
        q = q.filter(ScanRun.status == status)
    if domain:
        q = q.filter(ScanRun.domain.contains(domain))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return ScanListResponse(total=total, page=page, per_page=per_page, items=items)


@router.post("/", response_model=ScanResponse, status_code=201, summary="Create scan")
def create_scan(req: ScanCreateRequest, db: Session = Depends(get_db)):
    """Create a new scan run."""
    scan = ScanRun(domain=req.domain, scan_type=req.scan_type, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    progress = ScanProgress(scan_run_id=scan.id, status="queued")
    db.add(progress)
    db.commit()
    return scan


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get a specific scan by ID."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.put("/{scan_id}", response_model=ScanResponse, summary="Update scan")
def update_scan(scan_id: int, req: ScanUpdateRequest, db: Session = Depends(get_db)):
    """Update scan configuration."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if req.status:
        scan.status = req.status
    if req.scan_type:
        scan.scan_type = req.scan_type
    db.commit()
    db.refresh(scan)
    return scan


@router.delete("/{scan_id}", response_model=StatusResponse, summary="Delete scan")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan run."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return StatusResponse(status="deleted", message=f"Scan {scan_id} deleted")


@router.post("/{scan_id}/start", response_model=StatusResponse, summary="Start scan")
def start_scan(scan_id: int, db: Session = Depends(get_db)):
    """Start a pending scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Scan already running")
    scan.status = "running"
    db.commit()
    return StatusResponse(status="started", message=f"Scan {scan_id} started")


@router.post("/{scan_id}/stop", response_model=StatusResponse, summary="Stop scan")
def stop_scan(scan_id: int, db: Session = Depends(get_db)):
    """Stop a running scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.status = "stopped"
    db.commit()
    return StatusResponse(status="stopped", message=f"Scan {scan_id} stopped")


@router.get("/{scan_id}/progress", summary="Get scan progress")
def get_progress(scan_id: int, db: Session = Depends(get_db)):
    """Get real-time progress for a scan."""
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
