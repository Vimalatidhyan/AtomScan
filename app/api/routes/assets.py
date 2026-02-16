"""Asset management API routes.

Route order: static/specific paths before parameterised paths.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct
from typing import Optional

from app.db.database import get_db
from app.db.models import Subdomain, ScanRun, Vulnerability
from app.api.models.asset import AssetListResponse, AssetResponse
from app.api.models.common import StatusResponse

router = APIRouter()


# ── Static / aggregate routes (must precede /{asset_id}) ────────────────────

@router.get("/targets", summary="List distinct target domains")
def list_targets(db: Session = Depends(get_db)):
    """Return all distinct target domains that have been scanned."""
    rows = db.query(distinct(ScanRun.domain)).all()
    targets = [r[0] for r in rows if r[0]]
    return {"targets": targets, "total": len(targets)}


@router.get("/stats/{target:path}", summary="Asset stats for a target domain")
def asset_stats(target: str, db: Session = Depends(get_db)):
    """Return aggregated asset and finding stats for a target domain."""
    scan = (
        db.query(ScanRun)
        .filter(ScanRun.domain == target)
        .order_by(ScanRun.id.desc())
        .first()
    )
    if not scan:
        return {"target": target, "assets": 0, "vulnerabilities": 0,
                "critical": 0, "high": 0, "medium": 0, "low": 0}

    assets = db.query(func.count(Subdomain.id)).filter(
        Subdomain.scan_run_id == scan.id
    ).scalar() or 0

    vulns = db.query(Vulnerability).filter(Vulnerability.scan_run_id == scan.id).all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.severity or 0
        if sev >= 90:
            counts["critical"] += 1
        elif sev >= 70:
            counts["high"] += 1
        elif sev >= 40:
            counts["medium"] += 1
        else:
            counts["low"] += 1

    return {"target": target, "assets": assets, "vulnerabilities": len(vulns), **counts}


@router.get("/search", response_model=AssetListResponse, summary="Search assets")
def search_assets(
    q_str: str = Query(..., alias="q"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20),
    db: Session = Depends(get_db),
):
    q = db.query(Subdomain).filter(Subdomain.subdomain.contains(q_str))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


@router.get("/by-domain/{domain}", response_model=AssetListResponse, summary="Assets by domain")
def assets_by_domain(
    domain: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    q = db.query(Subdomain).filter(Subdomain.subdomain.contains(domain))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


@router.get("/high-risk", response_model=AssetListResponse, summary="High-risk assets")
def high_risk_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    min_vulns: int = Query(5, ge=0),
    scan_run_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    vuln_counts = (
        db.query(
            Vulnerability.subdomain_id,
            func.count(Vulnerability.id).label("vuln_count"),
        )
        .group_by(Vulnerability.subdomain_id)
        .subquery()
    )
    q = (
        db.query(Subdomain)
        .join(vuln_counts, Subdomain.id == vuln_counts.c.subdomain_id)
        .filter(vuln_counts.c.vuln_count >= min_vulns, Subdomain.is_alive == True)
    )
    if scan_run_id:
        q = q.filter(Subdomain.scan_run_id == scan_run_id)
    total = q.count()
    items = (
        q.order_by(vuln_counts.c.vuln_count.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


@router.get("/", response_model=AssetListResponse, summary="List assets")
def list_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_run_id: Optional[int] = None,
    is_alive: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    q = db.query(Subdomain)
    if scan_run_id:
        q = q.filter(Subdomain.scan_run_id == scan_run_id)
    if is_alive is not None:
        q = q.filter(Subdomain.is_alive == is_alive)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)


# ── Item routes (parameterised — must come AFTER static paths) ───────────────

@router.get("/{asset_id}", response_model=AssetResponse, summary="Get asset")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Subdomain).filter(Subdomain.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/{asset_id}/timeline", summary="Asset activity timeline")
def asset_timeline(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Subdomain).filter(Subdomain.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.subdomain_id == asset_id)
        .order_by(Vulnerability.discovered_at.asc())
        .all()
    )
    events = [
        {
            "event_type": "vulnerability",
            "severity": v.severity,
            "title": v.title,
            "timestamp": v.discovered_at.isoformat() if v.discovered_at else None,
        }
        for v in vulns
    ]
    return {
        "asset_id": asset_id,
        "subdomain": asset.subdomain,
        "is_alive": asset.is_alive,
        "events": events,
        "total": len(events),
    }
