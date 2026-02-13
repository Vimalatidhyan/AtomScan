"""Report generation API routes."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone
from pydantic import BaseModel
from backend.db.database import get_db
from backend.db.models import ScanRun, ComplianceReport
from backend.api.models.common import StatusResponse

router = APIRouter()

# Response models
class ReportSummary(BaseModel):
    id: int
    report_type: str
    scan_run_id: int
    generated_at: datetime
    
    class Config:
        from_attributes = True

class ReportListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[ReportSummary]

class ReportDetail(BaseModel):
    id: int
    report_type: str
    scan_run_id: int
    generated_at: datetime
    content: Optional[str] = None
    
    class Config:
        from_attributes = True

@router.get("/", response_model=ReportListResponse, summary="List reports")
def list_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """List available compliance reports with pagination."""
    q = db.query(ComplianceReport)
    if scan_run_id:
        q = q.filter(ComplianceReport.scan_run_id == scan_run_id)
    total = q.count()
    items = q.order_by(ComplianceReport.generated_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return ReportListResponse(total=total, page=page, per_page=per_page, items=items)

@router.post("/", response_model=StatusResponse, summary="Generate report")
def generate_report(scan_run_id: int, report_type: str = "technical", db: Session = Depends(get_db)):
    """Generate a new compliance report."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    report = ComplianceReport(scan_run_id=scan_run_id, report_type=report_type, generated_at=datetime.now(timezone.utc))
    db.add(report)
    db.commit()
    return StatusResponse(status="generated", message=f"Report created for scan {scan_run_id}")

@router.get("/{report_id}", response_model=ReportDetail, summary="Get report")
def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get a specific report by ID."""
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Report not found")
    return report

@router.get("/templates", summary="List report templates")
def list_templates():
    """List available report templates."""
    return {"templates": ["executive", "technical", "compliance", "risk_summary", "change_summary", "trend", "custom"]}
