"""Asset management API routes."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from backend.db.database import get_db
from backend.db.models import Subdomain
from backend.api.models.asset import AssetListResponse, AssetResponse
from backend.api.models.common import StatusResponse

router = APIRouter()

@router.get("/", response_model=AssetListResponse, summary="List assets")
def list_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    scan_run_id: Optional[int] = None,
    is_alive: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    """List all discovered assets."""
    q = db.query(Subdomain)
    if scan_run_id:
        q = q.filter(Subdomain.scan_run_id == scan_run_id)
    if is_alive is not None:
        q = q.filter(Subdomain.is_alive == is_alive)
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)

@router.get("/by-domain/{domain}", response_model=AssetListResponse, summary="Assets by domain")
def assets_by_domain(domain: str, page: int = Query(1, ge=1), per_page: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    """Get all assets for a specific domain."""
    q = db.query(Subdomain).filter(Subdomain.subdomain.contains(domain))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)

@router.get("/search", response_model=AssetListResponse, summary="Search assets")
def search_assets(q_str: str = Query(..., alias="q"), page: int = Query(1, ge=1), per_page: int = Query(20), db: Session = Depends(get_db)):
    """Search assets by keyword."""
    q = db.query(Subdomain).filter(Subdomain.subdomain.contains(q_str))
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)

@router.get("/high-risk", response_model=AssetListResponse, summary="High-risk assets")
def high_risk_assets(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    min_vulns: int = Query(5, ge=0),
    scan_run_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Get assets with high vulnerability count or risk score."""
    from backend.db.models import Vulnerability
    from sqlalchemy import func
    
    # Subquery to count vulnerabilities per asset
    vuln_counts = db.query(
        Vulnerability.subdomain_id,
        func.count(Vulnerability.id).label('vuln_count')
    ).group_by(Vulnerability.subdomain_id).subquery()
    
    q = db.query(Subdomain).join(
        vuln_counts,
        Subdomain.id == vuln_counts.c.subdomain_id
    ).filter(
        vuln_counts.c.vuln_count >= min_vulns,
        Subdomain.is_alive == True
    )
    
    if scan_run_id:
        q = q.filter(Subdomain.scan_run_id == scan_run_id)
    
    total = q.count()
    items = q.order_by(vuln_counts.c.vuln_count.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return AssetListResponse(total=total, page=page, per_page=per_page, items=items)

@router.get("/{asset_id}", response_model=AssetResponse, summary="Get asset")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    """Get a specific asset by ID."""
    asset = db.query(Subdomain).filter(Subdomain.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset

@router.get("/{asset_id}/timeline", summary="Asset timeline")
def asset_timeline(
    asset_id: int,
    event_type: Optional[str] = Query(None, description="Filter by event type: discovery, vulnerability, change"),
    from_date: Optional[str] = Query(None, description="Start date (ISO format)"),
    to_date: Optional[str] = Query(None, description="End date (ISO format)"),
    db: Session = Depends(get_db)
):
    """Get activity timeline for an asset with optional filters."""
    from backend.db.models import Vulnerability, ChangeEvent
    from datetime import datetime
    
    asset = db.query(Subdomain).filter(Subdomain.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    events = []
    
    # Add discovery event
    if not event_type or event_type == "discovery":
        events.append({
            "type": "discovery",
            "timestamp": asset.first_seen.isoformat() if asset.first_seen else None,
            "description": f"Asset discovered: {asset.subdomain}"
        })
    
    # Add vulnerability events
    if not event_type or event_type == "vulnerability":
        vulns = db.query(Vulnerability).filter(Vulnerability.subdomain_id == asset_id)
        
        # Apply date filters
        if from_date:
            vulns = vulns.filter(Vulnerability.discovered_at >= datetime.fromisoformat(from_date))
        if to_date:
            vulns = vulns.filter(Vulnerability.discovered_at <= datetime.fromisoformat(to_date))
        
        for vuln in vulns.all():
            events.append({
                "type": "vulnerability",
                "timestamp": vuln.discovered_at.isoformat() if vuln.discovered_at else None,
                "description": f"Vulnerability found: {vuln.title}",
                "severity": vuln.severity,
                "vuln_id": vuln.id
            })
    
    # Add change events
    if not event_type or event_type == "change":
        changes = db.query(ChangeEvent).filter(ChangeEvent.target_id == asset_id, ChangeEvent.target_type == "subdomain")
        
        if from_date:
            changes = changes.filter(ChangeEvent.detected_at >= datetime.fromisoformat(from_date))
        if to_date:
            changes = changes.filter(ChangeEvent.detected_at <= datetime.fromisoformat(to_date))
        
        for change in changes.all():
            events.append({
                "type": "change",
                "timestamp": change.detected_at.isoformat() if change.detected_at else None,
                "description": change.change_type,
                "details": change.old_value if hasattr(change, 'old_value') else None
            })
    
    # Sort events by timestamp
    events.sort(key=lambda x: x.get('timestamp') or '', reverse=True)
    
    return {
        "asset_id": asset_id,
        "subdomain": asset.subdomain,
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        "total_events": len(events),
        "events": events
    }
