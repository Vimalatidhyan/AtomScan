"""Vulnerability findings API routes."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from typing import Optional
from backend.db.database import get_db
from backend.db.models import Vulnerability
from backend.api.models.finding import FindingListResponse, FindingResponse, FindingUpdateRequest
from backend.api.models.common import StatusResponse

router = APIRouter()

@router.get("/", response_model=FindingListResponse, summary="List findings")
def list_findings(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_run_id: Optional[int] = None,
    severity_min: Optional[int] = Query(None, ge=0, le=100),
    vuln_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all vulnerability findings with optional filters."""
    q = db.query(Vulnerability)
    if scan_run_id:
        q = q.filter(Vulnerability.scan_run_id == scan_run_id)
    if severity_min is not None:
        q = q.filter(Vulnerability.severity >= severity_min)
    if vuln_type:
        q = q.filter(Vulnerability.vuln_type == vuln_type)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return FindingListResponse(total=total, page=page, per_page=per_page, items=items)

@router.get("/by-severity", summary="Findings grouped by severity")
def findings_by_severity(scan_run_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Get finding counts grouped by severity tier using SQL aggregation."""
    q = db.query(Vulnerability.severity)
    if scan_run_id:
        q = q.filter(Vulnerability.scan_run_id == scan_run_id)
    
    # Use SQL CASE to group by severity in database
    severity_case = case(
        (Vulnerability.severity >= 90, "critical"),
        (Vulnerability.severity >= 70, "high"),
        (Vulnerability.severity >= 40, "medium"),
        (Vulnerability.severity >= 10, "low"),
        else_="info"
    )
    
    results = db.query(
        severity_case.label("tier"),
        func.count().label("count")
    ).select_from(Vulnerability)
    
    if scan_run_id:
        results = results.filter(Vulnerability.scan_run_id == scan_run_id)
    
    results = results.group_by("tier").all()
    
    # Convert to dict
    groups = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for tier, count in results:
        groups[tier] = count
    
    return groups

@router.get("/by-type", summary="Findings grouped by type")
def findings_by_type(scan_run_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Get finding counts grouped by vulnerability type using SQL aggregation."""
    q = db.query(
        Vulnerability.vuln_type,
        func.count().label("count")
    )
    if scan_run_id:
        q = q.filter(Vulnerability.scan_run_id == scan_run_id)
    
    results = q.group_by(Vulnerability.vuln_type).all()
    return {vuln_type: count for vuln_type, count in results}

@router.get("/{finding_id}", response_model=FindingResponse, summary="Get finding")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """Get a specific vulnerability finding."""
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.put("/{finding_id}", response_model=FindingResponse, summary="Update finding")
def update_finding(finding_id: int, req: FindingUpdateRequest, db: Session = Depends(get_db)):
    """Update a vulnerability finding."""
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if req.severity is not None:
        finding.severity = req.severity
    if req.remediation:
        finding.remediation = req.remediation
    db.commit()
    db.refresh(finding)
    return finding

@router.delete("/{finding_id}", response_model=StatusResponse, summary="Delete finding")
def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    """Delete a vulnerability finding."""
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(finding)
    db.commit()
    return StatusResponse(status="deleted", message=f"Finding {finding_id} deleted")

@router.post("/{finding_id}/remediate", response_model=StatusResponse, summary="Mark in remediation")
def remediate_finding(finding_id: int, db: Session = Depends(get_db)):
    """Mark a finding as in remediation."""
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Actually update the database
    finding.status = "in_remediation"
    db.commit()
    db.refresh(finding)
    return StatusResponse(status="in_remediation", message=f"Finding {finding_id} marked for remediation")
