"""Vulnerability findings API routes.

Route order: static paths (/by-severity, /by-type, /domain/{target}/summary)
must be registered BEFORE parameterised paths (/{finding_id}) to avoid
FastAPI type-coercion shadowing.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from typing import Optional

from app.db.database import get_db
from app.db.models import Vulnerability, ScanRun
from app.api.models.finding import FindingListResponse, FindingResponse, FindingUpdateRequest
from app.api.models.common import StatusResponse

router = APIRouter()


def _severity_counts(vulns):
    """Aggregate vulnerability list into tier counts."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = v.severity or 0
        if sev >= 90:
            counts["critical"] += 1
        elif sev >= 70:
            counts["high"] += 1
        elif sev >= 40:
            counts["medium"] += 1
        elif sev >= 10:
            counts["low"] += 1
        else:
            counts["info"] += 1
    return counts


# ── Static / aggregate routes ────────────────────────────────────────────────

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
    severity_case = case(
        (Vulnerability.severity >= 90, "critical"),
        (Vulnerability.severity >= 70, "high"),
        (Vulnerability.severity >= 40, "medium"),
        (Vulnerability.severity >= 10, "low"),
        else_="info",
    )
    q = db.query(severity_case.label("tier"), func.count().label("count")).select_from(
        Vulnerability
    )
    if scan_run_id:
        q = q.filter(Vulnerability.scan_run_id == scan_run_id)
    results = q.group_by("tier").all()
    groups = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for tier, count in results:
        groups[tier] = count
    return groups


@router.get("/by-type", summary="Findings grouped by type")
def findings_by_type(scan_run_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Get finding counts grouped by vulnerability type."""
    q = db.query(Vulnerability.vuln_type, func.count().label("count"))
    if scan_run_id:
        q = q.filter(Vulnerability.scan_run_id == scan_run_id)
    results = q.group_by(Vulnerability.vuln_type).all()
    return {vuln_type: count for vuln_type, count in results}


@router.get("/domain/{target:path}/summary", summary="Findings summary for a target domain")
def findings_domain_summary(target: str, db: Session = Depends(get_db)):
    """Return severity-count summary for a specific target domain.

    Uses the most recent scan for the given domain.
    """
    return _findings_summary_for_target(target, db)


def _findings_summary_for_target(target: str, db: Session):
    """Shared logic for findings summary by target domain."""
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {"target": target, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_run_id == scan.id).all()
    counts = _severity_counts(vulns)
    return {"target": target, **counts, "total": len(vulns)}


def _findings_for_target(target: str, db: Session, page: int = 1, per_page: int = 100):
    """Return findings list for a target domain."""
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {"findings": [], "total": 0, "target": target}

    q = db.query(Vulnerability).filter(Vulnerability.scan_run_id == scan.id)
    total = q.count()
    vulns = q.offset((page - 1) * per_page).limit(per_page).all()
    findings = []
    for v in vulns:
        sev_val = v.severity or 0
        if sev_val >= 90:
            sev_label = "critical"
        elif sev_val >= 70:
            sev_label = "high"
        elif sev_val >= 40:
            sev_label = "medium"
        elif sev_val >= 10:
            sev_label = "low"
        else:
            sev_label = "info"
        findings.append({
            "id": v.id,
            "name": v.title,
            "title": v.title,
            "severity": sev_label,
            "severity_score": v.severity,
            "host": getattr(v, 'subdomain', None) and v.subdomain.subdomain if v.subdomain else target,
            "cve": v.cve_ids or "",
            "tool": v.vuln_type,
            "source": v.vuln_type,
            "description": v.description or "",
            "info": v.description or "",
            "remediation": v.remediation or "",
            "status": v.status or "open",
            "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
        })
    return {"findings": findings, "total": total, "target": target}


# ── Legacy UI compat routes — must come before /{finding_id} ─────────────────
# The dashboard-v2.js calls GET /api/v1/findings/{target}/summary
# and findings_v2.js calls GET /api/v1/findings/{target}

@router.get("/{target:path}/summary", summary="Findings summary (legacy UI compat)",
            include_in_schema=False)
def findings_summary_legacy(target: str, db: Session = Depends(get_db)):
    """Legacy alias: /{target}/summary → domain summary."""
    # Avoid matching integer IDs followed by /summary
    if target.replace("/", "").isdigit():
        raise HTTPException(status_code=404, detail="Not found")
    # Strip /domain/ prefix if present
    if target.startswith("domain/"):
        target = target[7:]
    return _findings_summary_for_target(target, db)


# ── Item routes (parameterised — must come AFTER all static paths) ───────────

@router.get("/{finding_id_or_target}", summary="Get finding or target findings")
def get_finding_or_target(finding_id_or_target: str, db: Session = Depends(get_db)):
    """Get a single finding by integer ID, or list findings for a target domain."""
    # If it's a pure integer, look up the finding
    if finding_id_or_target.isdigit():
        finding = db.query(Vulnerability).filter(Vulnerability.id == int(finding_id_or_target)).first()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        return finding
    # Otherwise treat as target domain
    return _findings_for_target(finding_id_or_target, db)


@router.put("/{finding_id}", response_model=FindingResponse, summary="Update finding")
def update_finding(
    finding_id: int, req: FindingUpdateRequest, db: Session = Depends(get_db)
):
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if req.severity is not None:
        finding.severity = req.severity
    if req.remediation:
        finding.remediation = req.remediation
    if req.status is not None:
        finding.status = req.status
    db.commit()
    db.refresh(finding)
    return finding


@router.delete("/{finding_id}", response_model=StatusResponse, summary="Delete finding")
def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(finding)
    db.commit()
    return StatusResponse(status="deleted", message=f"Finding {finding_id} deleted")


@router.post("/{finding_id}/remediate", response_model=StatusResponse, summary="Mark in remediation")
def remediate_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = "in_remediation"
    db.commit()
    db.refresh(finding)
    return StatusResponse(
        status="in_remediation",
        message=f"Finding {finding_id} marked for remediation",
    )
