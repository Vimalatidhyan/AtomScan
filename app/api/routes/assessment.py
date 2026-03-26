"""Assessment API routes — /api/assessment/{scan_id}/...

Each endpoint locates the scan output directory, calls the appropriate
extractor from output_ui_binder, and returns structured JSON.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import ScanRun
from app.api.helpers.output_ui_binder import (
    find_scan_dir,
    build_overview,
    extract_subdomains,
    extract_dns,
    extract_asn,
    extract_alive_hosts,
    extract_cloud,
    extract_cert_transparency,
    extract_directories,
    extract_urls,
    extract_javascript,
    extract_api_discovery,
    extract_secrets,
    extract_ports,
    extract_vulnerabilities,
    extract_ssl,
    extract_threat_intel,
    extract_compliance,
    extract_attack_graph,
    extract_change_detection,
    extract_whois,
    extract_tool_errors,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_scan(scan_id: int, db: Session) -> ScanRun:
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


def _require_dir(scan: ScanRun, scan_id: int):
    scan_dir = find_scan_dir(scan.domain, scan_id)
    if not scan_dir:
        raise HTTPException(
            status_code=404,
            detail=f"Output directory not found for scan {scan_id} (domain={scan.domain})",
        )
    return scan_dir


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/overview")
def get_overview(scan_id: int, db: Session = Depends(get_db)):
    """High-level count of discovered files per module."""
    scan = _get_scan(scan_id, db)
    return build_overview(scan.domain, scan_id)


@router.get("/{scan_id}/subdomains")
def get_subdomains(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_subdomains(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/dns")
def get_dns(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_dns(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/asn")
def get_asn(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_asn(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/whois")
def get_whois(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_whois(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/alive")
def get_alive_hosts(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_alive_hosts(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/cloud")
def get_cloud(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_cloud(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/certificates")
def get_certificates(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_cert_transparency(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/directories")
def get_directories(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_directories(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/urls")
def get_urls(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_urls(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/javascript")
def get_javascript(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_javascript(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/api-discovery")
def get_api_discovery(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_api_discovery(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/secrets")
def get_secrets(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_secrets(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/ports")
def get_ports(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_ports(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/vulnerabilities")
def get_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_vulnerabilities(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/ssl")
def get_ssl(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_ssl(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/threatintel")
def get_threatintel(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_threat_intel(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/compliance")
def get_compliance(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_compliance(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/attackgraph")
def get_attackgraph(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_attack_graph(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/change-detection")
def get_change_detection(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_change_detection(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}


@router.get("/{scan_id}/tool-errors")
def get_tool_errors(scan_id: int, db: Session = Depends(get_db)):
    scan = _get_scan(scan_id, db)
    scan_dir = _require_dir(scan, scan_id)
    data = extract_tool_errors(scan_dir)
    return {"status": "ok", "scan_id": scan_id, "domain": scan.domain, **data}
