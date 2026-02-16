"""Report generation API routes.

Route order matters: static paths (/templates) must be registered
BEFORE parameterized paths (/{report_id}) to avoid shadowing.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone
from pydantic import BaseModel, ConfigDict
from app.db.database import get_db
from app.db.models import ScanRun, ComplianceReport
from app.api.models.common import StatusResponse

router = APIRouter()

# ── Response models ──────────────────────────────────────────────────────────

VALID_TEMPLATES = [
    "executive",
    "technical",
    "compliance",
    "risk_summary",
    "change_summary",
    "trend",
    "custom",
]


class ReportSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_type: Optional[str] = None
    scan_run_id: Optional[int] = None
    generated_at: Optional[datetime] = None


class ReportListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[ReportSummary]


class ReportDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    report_type: Optional[str] = None
    scan_run_id: Optional[int] = None
    generated_at: Optional[datetime] = None
    content: Optional[str] = None


# ── Static routes first (must precede /{report_id}) ─────────────────────────

@router.get("/templates", summary="List report templates")
def list_templates():
    """List available report template names."""
    return {"templates": VALID_TEMPLATES}


# ── Collection routes ────────────────────────────────────────────────────────

@router.get("/", response_model=ReportListResponse, summary="List reports")
def list_reports(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_run_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """List available compliance reports with pagination."""
    q = db.query(ComplianceReport)
    if scan_run_id:
        q = q.filter(ComplianceReport.scan_run_id == scan_run_id)
    total = q.count()
    items = (
        q.order_by(ComplianceReport.generated_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return ReportListResponse(total=total, page=page, per_page=per_page, items=items)


@router.post("/", response_model=StatusResponse, summary="Generate report")
def generate_report(
    scan_run_id: int,
    report_type: str = "technical",
    db: Session = Depends(get_db),
):
    """Generate a new compliance report for a completed scan."""
    if report_type not in VALID_TEMPLATES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid report_type. Must be one of: {VALID_TEMPLATES}",
        )
    scan = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = ComplianceReport(
        scan_run_id=scan_run_id,
        report_type=report_type,
        generated_at=datetime.now(timezone.utc),
    )
    db.add(report)
    db.commit()
    return StatusResponse(
        status="generated",
        message=f"Report of type '{report_type}' created for scan {scan_run_id}",
    )


# ── Item routes (parameterised — must come AFTER all static paths) ───────────

@router.get("/{report_id}", response_model=ReportDetail, summary="Get report")
def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get a specific report by integer ID."""
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report
