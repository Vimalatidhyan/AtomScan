"""Scan management API routes.

Supports two request styles for scan creation:
  - JSON body: {"domain": "example.com", "scan_type": "full"}  (canonical)
  - Query params: ?target=example.com&phases=1,2,3,4           (legacy UI compat)
"""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone

from app.db.database import get_db
from app.db.models import ScanRun, ScanProgress, ScanJob, ScanEvent, DNSRecord, ISPLocation
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
    """Create ScanProgress + ScanJob in the same transaction as the caller.

    Defensively removes any pre-existing rows for this scan_run_id before
    inserting new ones.  This prevents UNIQUE constraint violations when SQLite
    reuses auto-increment IDs that belonged to previously deleted scans which
    left orphaned child-table rows (due to the old broken rollback logic).
    """
    # Remove stale progress/job rows that may be orphaned from a prior scan
    # with the same ID (SQLite INTEGER PRIMARY KEY can reuse deleted IDs).
    db.execute(text("DELETE FROM scan_progress WHERE scan_run_id = :sid"), {"sid": scan.id})
    db.execute(text("DELETE FROM scan_jobs WHERE scan_run_id = :sid"), {"sid": scan.id})

    progress = ScanProgress(scan_run_id=scan.id, status="queued")
    db.add(progress)
    job = ScanJob(
        scan_run_id=scan.id,
        status="queued",
        queued_at=datetime.now(timezone.utc),
    )
    db.add(job)


# Ordered phase names matching shell modules 01-04
_PHASE_NAMES = [
    "1_discovery",
    "2_intel",
    "3_content",
    "4_vulnscan",
]


def _build_phases(phase_num: int, status: str) -> dict:
    """Build a phases dict from the integer phase counter and scan status.

    phase_num indicates how many phases have completed (0-4).
    For a 'completed' scan with phase=0 (legacy/stuck data) treat all as done.
    """
    if status == "completed":
        # All phases done regardless of stored phase counter
        return {name: True for name in _PHASE_NAMES}
    if status == "failed":
        return {name: (i < phase_num) for i, name in enumerate(_PHASE_NAMES)}
    # running / queued — phases up to phase_num-1 are done, rest are pending
    return {name: (i < phase_num) for i, name in enumerate(_PHASE_NAMES)}


def _scan_to_dict(scan: ScanRun) -> dict:
    """Return scan data including legacy field aliases expected by the UI."""
    phase_num = scan.phase or 0
    status = scan.status or "queued"
    # For completed scans that have stale phase=0, report phase as 4
    display_phase = 4 if status == "completed" else phase_num
    phases = _build_phases(phase_num, status)
    return {
        "id": scan.id,
        "scan_id": str(scan.id),          # legacy alias used by dashboard-v2.js
        "domain": scan.domain,
        "target": scan.domain,            # legacy alias used by dashboard-v2.js
        "scan_type": scan.scan_type,
        "status": status,
        "risk_score": scan.risk_score,
        "phase": display_phase,
        "started_at": scan.created_at.isoformat() if scan.created_at else None,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "phases": phases,
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
async def create_scan(
    request: Request,
    # Query params (legacy UI compat)
    target: Optional[str] = Query(None, description="Target domain (legacy UI)"),
    phases: Optional[str] = Query(None, description="Comma-separated phases (legacy UI)"),
    test_mode: Optional[bool] = Query(False, description="Test mode flag (legacy UI)"),
    db: Session = Depends(get_db),
):
    # Safety guard: test_mode only works when explicitly enabled via the
    # TECHNIEUM_TEST_MODE=1 environment variable.  This prevents accidental
    # use of mock data through a stale UI checkbox / localStorage value.
    import os as _os
    if test_mode and not _os.environ.get("TECHNIEUM_TEST_MODE", "").strip() in ("1", "true", "yes"):
        test_mode = False
    """Create a new scan.

    Accepts either:
    - POST /scans/ with JSON body {"domain": "...", "scan_type": "..."}
    - POST /scans/?target=example.com&phases=1,2,3  (legacy dashboard format)
    """
    domain = None
    scan_type = "full"
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if isinstance(body, dict) and body.get("domain"):
            domain = body["domain"]
            scan_type = body.get("scan_type", "full")
    if domain is None and target:
        # Legacy query-param format
        from pydantic import ValidationError
        try:
            validated = ScanCreateRequest(domain=target, scan_type=_phases_to_scan_type(phases))
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        domain = validated.domain
        scan_type = validated.scan_type
    if not domain:
        raise HTTPException(
            status_code=422,
            detail="Either JSON body with 'domain' or query param 'target' is required",
        )

    if test_mode:
        # Test mode: create a scan and immediately mark it completed with
        # realistic-looking mock data so the UI can show results instantly
        # without running real tools.
        scan = ScanRun(domain=domain, scan_type=scan_type, status="completed",
                       phase=4, risk_score=42)
        db.add(scan)
        db.flush()
        # Insert mock progress so the detail panel renders correctly
        db.execute(text("DELETE FROM scan_progress WHERE scan_run_id = :sid"), {"sid": scan.id})
        progress = ScanProgress(
            scan_run_id=scan.id,
            status="completed",
            current_phase=4,
            progress_percentage=100,
            subdomains_found=12,
            ports_found=8,
            vulnerabilities_found=3,
        )
        db.add(progress)
        for msg in [
            "[test] Scan started in test-mode (mock data)",
            "[test] Discovery phase complete — 12 subdomains found",
            "[test] Intel phase complete",
            "[test] Content phase complete",
            "[test] Vulnerability scan complete — 3 findings",
            "[test] Scan finished successfully",
        ]:
            db.add(ScanEvent(
                scan_run_id=scan.id,
                event_type="log",
                level="info",
                message=msg,
                phase=4,
                created_at=datetime.now(timezone.utc),
            ))
        db.commit()
        db.refresh(scan)
        return _scan_to_dict(scan)

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

    # Bulk-delete every child table via raw SQL so we never rely on ORM
    # cascade or SQLite FK enforcement (which is off by default).
    # Tables are ordered so grandchildren are deleted before parents.
    #
    # NOTE: compliance_findings uses report_id (FK → compliance_reports.id),
    #       not scan_run_id, so it must be handled via a subquery.
    #       audit_logs has no scan_run_id column (standalone table) — skip it.
    _child_tables = [
        "scan_events",
        "scan_jobs",
        "scan_progress",
        "baseline_snapshots",
        "malware_indicators",
        "data_leaks",
        "compliance_reports",
        "asset_snapshots",
        "risk_scores",
        "threat_intel_data",
        "isp_locations",
        "dns_records",
        "domain_technologies",
        "vulnerability_metadata",
        "vulnerabilities",
        "http_headers",
        "port_scans",
        "subdomains",
        "scan_runner_metadata",
        "saved_reports",
    ]

    # Delete compliance evidence/findings via subquery
    # (their FKs point to compliance_reports.id, not scan_run_id directly)
    for _subq_table, _subq_col, _subq_parent in [
        ("compliance_evidence",  "compliance_report_id", "compliance_reports"),
        ("compliance_findings",  "report_id",            "compliance_reports"),
    ]:
        try:
            db.execute(text("SAVEPOINT sp_subq"))
            db.execute(
                text(
                    f"DELETE FROM {_subq_table}"
                    f" WHERE {_subq_col} IN"
                    f" (SELECT id FROM {_subq_parent} WHERE scan_run_id = :sid)"
                ),
                {"sid": scan_id},
            )
            db.execute(text("RELEASE SAVEPOINT sp_subq"))
        except Exception:
            db.execute(text("ROLLBACK TO SAVEPOINT sp_subq"))

    for table in _child_tables:
        try:
            db.execute(text("SAVEPOINT sp_del"))
            db.execute(text(f"DELETE FROM {table} WHERE scan_run_id = :sid"), {"sid": scan_id})
            db.execute(text("RELEASE SAVEPOINT sp_del"))
        except Exception:
            # Table may not exist yet (schema evolution) — roll back only this
            # single statement so prior deletes in the transaction are preserved.
            db.execute(text("ROLLBACK TO SAVEPOINT sp_del"))

    db.delete(scan)
    db.commit()
    return StatusResponse(status="deleted", message=f"Scan {scan_id} deleted")


@router.post("/{scan_id}/start", response_model=StatusResponse, summary="Start scan")
def start_scan(scan_id: int, db: Session = Depends(get_db)):
    """Enqueue a scan job (or re-enqueue a completed/failed/stopped scan).

    Resets all transient state so the UI starts fresh:
    - Clears old scan_events (mock events from test_mode or previous run logs)
    - Resets scan_progress to queued with 0%
    - Resets scan.phase, completed_at, risk_score
    - Creates a new ScanJob unless one is already active
    """
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "running":
        raise HTTPException(status_code=400, detail="Scan already running")

    # ── Reset scan metadata so UI shows a fresh run ──
    scan.phase = 0
    scan.completed_at = None
    scan.risk_score = None

    # ── Clear old log events so the log stream starts empty ──
    db.execute(
        text("DELETE FROM scan_events WHERE scan_run_id = :sid"),
        {"sid": scan_id},
    )

    # ── Reset progress record so progress bar shows 0% / queued ──
    db.execute(
        text("DELETE FROM scan_progress WHERE scan_run_id = :sid"),
        {"sid": scan_id},
    )
    db.add(ScanProgress(
        scan_run_id=scan_id,
        status="queued",
        current_phase=0,
        progress_percentage=0,
    ))

    # ── Mark any stale jobs as superseded so worker ignores them ──
    db.execute(
        text(
            "UPDATE scan_jobs SET status='superseded'"
            " WHERE scan_run_id = :sid AND status IN ('queued','running','done','failed','stopped')"
        ),
        {"sid": scan_id},
    )

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


@router.get("/{scan_id}/assessment", summary="Get assessment panel data")
def get_assessment(scan_id: int, db: Session = Depends(get_db)):
    """Return structured assessment data (live hosts, ASN, cloud, CT, httpx) for a scan.

    Reads the persisted ScanEvent rows with structured data payloads so the
    UI can populate the assessment panels immediately on page load, without
    waiting for the full SSE stream to replay hundreds of log events.

    Falls back to reading phase1_summary.json directly from the output
    directory when no ScanEvent rows exist (e.g. scans completed before
    event emission was added).
    """
    import json as _json
    from pathlib import Path
    import os, re

    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Query all structured data events for this scan
    structured_types = ["alive_hosts", "asn_data", "cloud_data", "ct_data", "httpx_details"]
    events = (
        db.query(ScanEvent)
        .filter(
            ScanEvent.scan_run_id == scan_id,
            ScanEvent.event_type.in_(structured_types),
        )
        .order_by(ScanEvent.id.desc())  # latest first so we get the newest data
        .all()
    )

    result = {
        "scan_id": scan_id,
        "target": scan.domain,
        "status": scan.status,
        "live_hosts": None,
        "asn": None,
        "cloud": None,
        "ct": None,
        "httpx_details": None,
    }

    # Use the most recent event for each type
    seen = set()
    for ev in events:
        if ev.event_type in seen:
            continue
        seen.add(ev.event_type)
        data = {}
        if ev.data:
            try:
                data = _json.loads(ev.data)
            except (ValueError, TypeError):
                pass
        if ev.event_type == "alive_hosts":
            result["live_hosts"] = data
        elif ev.event_type == "asn_data":
            result["asn"] = data
        elif ev.event_type == "cloud_data":
            result["cloud"] = data
        elif ev.event_type == "ct_data":
            result["ct"] = data
        elif ev.event_type == "httpx_details":
            result["httpx_details"] = data

    # ── File-based fallback ──────────────────────────────────────────────
    # Fill in any missing panel data from phase1_summary.json on disk.
    # This covers legacy scans and panels that weren't emitted as events.
    missing = [k for k in ("live_hosts", "asn", "cloud", "ct", "httpx_details") if not result[k]]
    if missing:
        repo_root = Path(__file__).resolve().parents[3]
        output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
        slug = f"{scan.domain.replace('.', '_')}_scan_{scan_id}"
        for candidate in (output_base / slug / "phase1_summary.json",
                          output_base / slug / "phase1_discovery" / "phase1_summary.json"):
            if candidate.is_file():
                try:
                    p1 = _json.loads(candidate.read_text(encoding="utf-8", errors="ignore"))
                    _ansi_re = re.compile(r'\x1b\[[0-9;]*m')
                    def _clean(items):
                        return [_ansi_re.sub('', s) if isinstance(s, str) else s for s in items]
                    if not result["live_hosts"]:
                        urls = p1.get("alive_urls") or []
                        if urls:
                            result["live_hosts"] = {"urls": urls[:500], "count": len(urls)}
                    if not result["asn"]:
                        asn = p1.get("asn") or {}
                        result["asn"] = {
                            "cidrs": (asn.get("cidrs") or [])[:200],
                            "ip_count": asn.get("ip_count") or 0,
                            "ips_sample": asn.get("ips_sample") or [],
                        }
                    if not result["cloud"]:
                        cloud = p1.get("cloud") or {}
                        result["cloud"] = {
                            "total": cloud.get("total") or 0,
                            "assets": _clean((cloud.get("assets") or [])[:200]),
                            "aws":    _clean(cloud.get("aws") or []),
                            "azure":  _clean(cloud.get("azure") or []),
                            "gcp":    _clean(cloud.get("gcp") or []),
                        }
                    if not result["ct"]:
                        ct = p1.get("ct_sources") or {}
                        if ct:
                            result["ct"] = ct
                    if not result["httpx_details"]:
                        hx = p1.get("httpx_details") or []
                        if hx:
                            result["httpx_details"] = {"hosts": hx[:500]}
                except Exception:
                    pass
                break

    # Strip ANSI escape codes from cloud data (covers old events stored with ANSI)
    if result.get("cloud"):
        _ansi_clean = re.compile(r'\x1b\[[0-9;]*m')
        cloud = result["cloud"]
        for key in ("assets", "aws", "azure", "gcp"):
            if cloud.get(key):
                cloud[key] = [_ansi_clean.sub('', s) if isinstance(s, str) else s for s in cloud[key]]

    return result


@router.get("/{scan_id}/dns-records", summary="Get DNS records with IP/ASN/Location data")
def get_dns_records(scan_id: int, db: Session = Depends(get_db)):
    """Return DNS resolution data from dnsx_resolved.json: subdomain → IP → CNAME/TTL."""
    import json as _json
    from pathlib import Path
    import os
    
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    dns_records = []
    
    try:
        repo_root = Path(__file__).resolve().parents[3]
        output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
        slug = f"{scan.domain.replace('.', '_')}_scan_{scan_id}"
        
        # Try to find dnsx_resolved.json in phase1_discovery
        dnsx_files = [
            output_base / slug / "phase1_discovery" / "dnsx_resolved.json",
            output_base / slug / "dnsx_resolved.json",
        ]
        
        for dnsx_file in dnsx_files:
            if dnsx_file.is_file():
                # Parse JSONL file (one JSON per line)
                content = dnsx_file.read_text(encoding="utf-8", errors="ignore").strip()
                for line in content.split('\n'):
                    if not line.strip():
                        continue
                    try:
                        record = _json.loads(line)
                        host = record.get("host", "")
                        ttl = record.get("ttl")
                        resolver = record.get("resolver", [])
                        cname = record.get("cname", [])
                        a_records = record.get("a", [])
                        status = record.get("status_code", "UNKNOWN")
                        
                        # Add entry for each IP address
                        if a_records:
                            for ip in a_records:
                                dns_records.append({
                                    "subdomain": host,
                                    "ip": ip,
                                    "cname": cname[0] if cname else None,
                                    "ttl": ttl,
                                    "resolver": resolver[0] if resolver else "Unknown",
                                    "status": status,
                                    "raw_record": record.get("all", []),
                                })
                        else:
                            # No A records but we have the DNS entry
                            dns_records.append({
                                "subdomain": host,
                                "ip": None,
                                "cname": cname[0] if cname else None,
                                "ttl": ttl,
                                "resolver": resolver[0] if resolver else "Unknown",
                                "status": status,
                                "raw_record": record.get("all", []),
                            })
                    except (ValueError, KeyError):
                        continue
                break
    except Exception:
        pass

    return {
        "scan_id": scan_id,
        "target": scan.domain,
        "records": dns_records,
        "count": len(dns_records),
    }


@router.get("/{scan_id}/certificate-records", summary="Get certificate transparency results")
def get_certificate_records(scan_id: int, db: Session = Depends(get_db)):
    """Return CT certificate records discovered for this scan from ct/ directory."""
    import json as _json
    from pathlib import Path
    import os
    
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    certificates = []
    
    try:
        repo_root = Path(__file__).resolve().parents[3]
        output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
        slug = f"{scan.domain.replace('.', '_')}_scan_{scan_id}"
        
        # Check for CT directory with certificate files
        ct_dir = output_base / slug / "phase1_discovery" / "ct"
        
        if ct_dir.is_dir():
            # Parse certspotter.txt and crtsh.txt files
            for source_file in ["certspotter.txt", "crtsh.txt"]:
                source = "certspotter" if source_file == "certspotter.txt" else "crt.sh"
                cert_file = ct_dir / source_file
                
                if cert_file.is_file():
                    try:
                        content = cert_file.read_text(encoding="utf-8", errors="ignore").strip()
                        for line in content.split('\n'):
                            domain = line.strip()
                            if domain and not domain.startswith('#'):
                                certificates.append({
                                    "domain": domain,
                                    "issuer": None,
                                    "ca": None,
                                    "valid_from": None,
                                    "valid_to": None,
                                    "fingerprint": None,
                                    "sans": [],
                                    "source": source,
                                })
                    except Exception:
                        continue
        
        # Also try phase1_summary.json if it has detailed certificate data
        phase1_file = output_base / slug / "phase1_summary.json"
        if not phase1_file.is_file():
            phase1_file = output_base / slug / "phase1_discovery" / "phase1_summary.json"
        
        if phase1_file.is_file():
            try:
                p1_data = _json.loads(phase1_file.read_text(encoding="utf-8", errors="ignore"))
                # Check for detailed certs_crtsh and certs_certspotter arrays (if available)
                for source, cert_key in [("crt.sh", "certs_crtsh"), ("certspotter", "certs_certspotter")]:
                    if cert_key in p1_data and isinstance(p1_data[cert_key], list):
                        for cert in p1_data[cert_key]:
                            if isinstance(cert, dict):
                                certificates.append({
                                    "domain": cert.get("common_name") or cert.get("cn"),
                                    "issuer": cert.get("issuer_name") or cert.get("issuer"),
                                    "ca": cert.get("ca") or cert.get("issuer_name"),
                                    "valid_from": cert.get("not_before") or cert.get("valid_from"),
                                    "valid_to": cert.get("not_after") or cert.get("valid_to"),
                                    "fingerprint": cert.get("fingerprint") or cert.get("sha256"),
                                    "sans": cert.get("matching_identities") or cert.get("sans") or [],
                                    "source": source,
                                })
            except Exception:
                pass

    except Exception:
        pass

    # Remove duplicates while preserving order
    seen = set()
    unique_certs = []
    for cert in certificates:
        key = (cert.get("domain"), cert.get("source"))
        if key not in seen:
            seen.add(key)
            unique_certs.append(cert)

    return {
        "scan_id": scan_id,
        "target": scan.domain,
        "certificates": unique_certs,
        "count": len(unique_certs),
    }


@router.get("/{scan_id}/asn-records", summary="Get ASN and IP range data")
def get_asn_records(scan_id: int, db: Session = Depends(get_db)):
    """Return ASN and IP data from asn_by_ip.txt file."""
    import json as _json
    from pathlib import Path
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    asn_records = []
    file_found = False
    
    try:
        repo_root = Path(__file__).resolve().parents[3]
        output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
        domain_slug = scan.domain.replace('.', '_')
        
        # Try exact slug first (pattern: domain_scan_id)
        slugs_to_try = [
            f"{domain_slug}_scan_{scan_id}",  # apra_gov_au_scan_3
            f"{domain_slug}_{scan_id}",        # trutrip_co_1
        ]
        
        logger.info(f"ASN: Looking for scan {scan_id} ({scan.domain}) in {output_base}")
        
        # Try each slug pattern
        found_dir = None
        for slug in slugs_to_try:
            logger.info(f"ASN: Trying slug pattern: {slug}")
            scan_dir = output_base / slug
            if scan_dir.is_dir():
                found_dir = scan_dir
                logger.info(f"ASN: Found directory: {scan_dir}")
                break
        
        # If no exact match, search for a directory containing the domain
        if not found_dir:
            logger.info(f"ASN: No exact slug match, searching for directories containing {domain_slug}")
            for d in output_base.iterdir():
                if d.is_dir() and domain_slug.lower() in d.name.lower():
                    found_dir = d
                    logger.info(f"ASN: Found directory by domain search: {d}")
                    break
        
        if not found_dir:
            logger.warning(f"ASN: No directory found for scan {scan_id} ({domain_slug})")
        else:
            # Look for ASN files in phase2_intel/osint directory (try multiple naming patterns)
            asn_files = [
                found_dir / "phase2_intel" / "osint" / "asn_by_ip.txt",
                found_dir / "phase2_intel" / "osint" / "asn_info.txt",
                found_dir / "phase2_intel" / "asn_by_ip.txt",
                found_dir / "phase2_intel" / "asn_info.txt",
                found_dir / "phase1_discovery" / "asn" / "asn_ips.txt",
                found_dir / "phase1_discovery" / "asn" / "asn_cidrs.txt",
                found_dir / "asn_by_ip.txt",
                found_dir / "asn_info.txt",
            ]
            
            for asn_file in asn_files:
                logger.info(f"ASN: Checking {asn_file}")
                if asn_file.is_file():
                    logger.info(f"ASN: Found file at {asn_file}")
                    file_found = True
                    try:
                        content = asn_file.read_text(encoding="utf-8", errors="ignore").strip()
                        lines = content.split('\n')
                        logger.info(f"ASN: Parsing {len(lines)} lines from {asn_file.name}")
                        
                        for line in lines:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            
                            # Parse: IP | ASN | Organization
                            parts = [p.strip() for p in line.split('|')]
                            if len(parts) >= 3:
                                ip = parts[0]
                                asn = parts[1]
                                org = parts[2]
                                
                                asn_records.append({
                                    "ip": ip,
                                    "asn": asn if asn != "unknown" else None,
                                    "organization": org if org != "unknown" else None,
                                    "source": "asn_by_ip",
                                })
                            elif len(parts) == 2:
                                ip = parts[0]
                                asn = parts[1]
                                asn_records.append({
                                    "ip": ip,
                                    "asn": asn if asn != "unknown" else None,
                                    "organization": None,
                                    "source": "asn_by_ip",
                                })
                            elif len(parts) == 1 and parts[0]:
                                # Support phase1 ASN files (asn_ips.txt/asn_cidrs.txt) where
                                # each line is a plain IP/CIDR value.
                                asn_records.append({
                                    "ip": parts[0],
                                    "asn": None,
                                    "organization": None,
                                    "source": "asn_by_ip",
                                })
                        logger.info(f"ASN: Parsed {len(asn_records)} records")
                    except Exception as e:
                        logger.error(f"ASN: Error parsing file: {e}")
                        continue
                    break
            
            if not file_found:
                logger.warning(f"ASN: No asn_by_ip.txt file found in {found_dir}")
    except Exception as e:
        logger.error(f"ASN: Unexpected error: {e}")
        pass

    # Remove duplicates while preserving order
    seen = set()
    unique_records = []
    for rec in asn_records:
        key = rec["ip"]
        if key not in seen:
            seen.add(key)
            unique_records.append(rec)

    logger.info(f"ASN: Returning {len(unique_records)} unique records for scan {scan_id}")
    return {
        "scan_id": scan_id,
        "target": scan.domain,
        "asn_records": unique_records,
        "count": len(unique_records),
    }


@router.get("/{scan_id}/whois-data", summary="Get WHOIS domain registration data")
def get_whois_data(scan_id: int, db: Session = Depends(get_db)):
    """Return parsed WHOIS data from whois.txt: domain ownership, registrar, contact info, nameservers."""
    from pathlib import Path
    import os
    import logging
    
    logger = logging.getLogger(__name__)
    
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    whois_data = {
        "scan_id": scan_id,
        "target": scan.domain,
        "domain_info": {},
        "registrant_info": {},
        "contact_info": {},
        "name_servers": [],
    }
    
    try:
        repo_root = Path(__file__).resolve().parents[3]
        output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
        domain_slug = scan.domain.replace('.', '_')
        
        # Try exact slug first (pattern: domain_scan_id)
        slugs_to_try = [
            f"{domain_slug}_scan_{scan_id}",  # apra_gov_au_scan_3
            f"{domain_slug}_{scan_id}",        # trutrip_co_1
        ]
        
        logger.info(f"WHOIS: Looking for scan {scan_id} ({scan.domain}) in {output_base}")
        
        # Try each slug pattern
        found_dir = None
        for slug in slugs_to_try:
            logger.info(f"WHOIS: Trying slug pattern: {slug}")
            scan_dir = output_base / slug
            if scan_dir.is_dir():
                found_dir = scan_dir
                logger.info(f"WHOIS: Found directory: {scan_dir}")
                break
        
        # If no exact match, search for a directory containing the domain
        if not found_dir:
            logger.info(f"WHOIS: No exact slug match, searching for directories containing {domain_slug}")
            for d in output_base.iterdir():
                if d.is_dir() and domain_slug.lower() in d.name.lower():
                    found_dir = d
                    logger.info(f"WHOIS: Found directory by domain search: {d}")
                    break
        
        if not found_dir:
            logger.warning(f"WHOIS: No directory found for scan {scan_id} ({domain_slug})")
            return whois_data
        
        # Try to find whois.txt in phase1_discovery (try multiple naming patterns)
        whois_files = [
            found_dir / "phase0_prescan" / "whois.txt",
            found_dir / "phase1_discovery" / "whois.txt",
            found_dir / "phase1_discovery" / "whois_info.txt",
            found_dir / "phase1_discovery" / "domain_whois.txt",
            found_dir / "whois.txt",
            found_dir / "whois_info.txt",
        ]
        
        whois_content = None
        for whois_file in whois_files:
            logger.info(f"WHOIS: Checking {whois_file}")
            if whois_file.is_file():
                logger.info(f"WHOIS: Found file at {whois_file}")
                whois_content = whois_file.read_text(encoding="utf-8", errors="ignore")
                break
        
        if not whois_content:
            logger.warning(f"WHOIS: No file found for scan {scan_id}")
            return whois_data  # Return empty structure if no file found
        
        # Parse WHOIS text format (key: value pairs)
        lines = whois_content.split('\n')
        nameservers = {}  # Use dict to pair NS names with IPs
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('>>>'):
                continue
            
            if ':' in line:
                parts = line.split(':', 1)
                key = parts[0].strip().lower()
                value = parts[1].strip() if len(parts) > 1 else ""
                
                # Domain information
                if key == 'domain name':
                    whois_data['domain_info']['domain_name'] = value
                elif key == 'registry domain id':
                    whois_data['domain_info']['registry_domain_id'] = value
                elif key == 'registrar name':
                    whois_data['domain_info']['registrar'] = value
                elif key == 'last modified':
                    whois_data['domain_info']['last_modified'] = value
                elif key == 'dnssec':
                    whois_data['domain_info']['dnssec'] = value
                elif key == 'status':
                    # Can have multiple status lines; extract just the status code
                    status_code = value.split()[0] if value else ""
                    if status_code and 'status' not in whois_data['domain_info']:
                        whois_data['domain_info']['status'] = status_code
                    elif status_code:
                        # Append to existing if multiple statuses
                        if isinstance(whois_data['domain_info'].get('status'), list):
                            whois_data['domain_info']['status'].append(status_code)
                        else:
                            whois_data['domain_info']['status'] = [
                                whois_data['domain_info']['status'],
                                status_code
                            ]
                
                # Registrant information
                elif key == 'registrant':
                    whois_data['registrant_info']['name'] = value
                elif key == 'registrant contact name':
                    whois_data['registrant_info']['contact_name'] = value
                elif key == 'registrant organization':
                    whois_data['registrant_info']['organization'] = value
                elif key == 'eligibility type':
                    whois_data['registrant_info']['eligibility_type'] = value
                
                # Contact information
                elif key == 'registrar abuse contact email':
                    whois_data['contact_info']['abuse_email'] = value
                elif key == 'registrar abuse contact phone':
                    whois_data['contact_info']['abuse_phone'] = value
                elif key == 'tech contact name':
                    whois_data['contact_info']['tech_contact'] = value
                
                # Name servers — track sequence for pairing
                elif key == 'name server':
                    # Create entry for this nameserver
                    if value not in nameservers:
                        nameservers[value] = {'name': value, 'ip': None}
                elif key == 'name server ip':
                    # IP without a corresponding name - find the last NS and assign
                    if nameservers:
                        last_ns_name = list(nameservers.keys())[-1]
                        nameservers[last_ns_name]['ip'] = value
        
        # Convert dict to list
        whois_data['name_servers'] = list(nameservers.values())
        logger.info(f"WHOIS: Parsed {len(whois_data['domain_info'])} domain fields, {len(whois_data['registrant_info'])} registrant fields, {len(whois_data['contact_info'])} contact fields, {len(whois_data['name_servers'])} nameservers")
        
    except Exception as e:
        logger.error(f"WHOIS: Error parsing data: {e}")
        pass

    logger.info(f"WHOIS: Returning data for scan {scan_id}: has_domain={len(whois_data['domain_info'])>0}, has_contact={len(whois_data['contact_info'])>0}")
    return whois_data


@router.get("/{scan_id}/scan-details", summary="Get aggregated scan details/assets")
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    """Return aggregated scan details: hosts, IPs, ports, technologies, status."""
    import json as _json
    from pathlib import Path
    import os
    
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = []
    
    try:
        repo_root = Path(__file__).resolve().parents[3]
        output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
        slug = f"{scan.domain.replace('.', '_')}_scan_{scan_id}"
        
        # Try to read httpx_alive.json for detailed host information
        httpx_file = output_base / slug / "phase1_discovery" / "httpx_alive.json"
        if not httpx_file.is_file():
            httpx_file = output_base / slug / "httpx_alive.json"
        
        if httpx_file.is_file():
            try:
                # httpx_alive.json is JSONL format (one JSON per line)
                content = httpx_file.read_text(encoding="utf-8", errors="ignore").strip()
                for line in content.split('\n'):
                    if not line.strip():
                        continue
                    try:
                        entry = _json.loads(line)
                        asset = {
                            "host": entry.get("url") or entry.get("input"),
                            "ip": entry.get("ip"),
                            "port": entry.get("port"),
                            "status_code": entry.get("status_code"),
                            "title": entry.get("title"),
                            "webserver": entry.get("webserver"),
                            "technology": entry.get("technologies") or entry.get("technology"),
                            "source": "httpx",
                            "timestamp": entry.get("timestamp"),
                        }
                        assets.append(asset)
                    except (ValueError, KeyError):
                        continue
            except Exception:
                pass

    except Exception:
        pass

    return {
        "scan_id": scan_id,
        "target": scan.domain,
        "assets": assets,
        "count": len(assets),
    }


@router.post("/{scan_id}/pause", response_model=StatusResponse, summary="Pause scan")
def pause_scan(scan_id: int, db: Session = Depends(get_db)):
    """Pause a running scan.

    Sets the scan status to 'paused'.  The worker detects this on its next
    output-line poll and sends SIGSTOP to the harness process group, freezing
    all child tools until a resume is issued.
    """
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "running":
        raise HTTPException(status_code=400, detail=f"Cannot pause scan in '{scan.status}' state")

    scan.status = "paused"

    # Mark active jobs as paused
    active_jobs = (
        db.query(ScanJob)
        .filter(
            ScanJob.scan_run_id == scan_id,
            ScanJob.status == "running",
        )
        .all()
    )
    for job in active_jobs:
        job.status = "paused"

    # Update progress record
    progress = db.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first()
    if progress:
        progress.status = "paused"

    db.commit()

    # Emit a log event so the UI stream shows the pause
    db.add(ScanEvent(
        scan_run_id=scan_id,
        event_type="log",
        level="info",
        message="[PAUSE] Scan paused by user",
        created_at=datetime.now(timezone.utc),
    ))
    db.commit()

    return StatusResponse(status="paused", message=f"Scan {scan_id} paused")


@router.post("/{scan_id}/resume", response_model=StatusResponse, summary="Resume scan")
def resume_scan(scan_id: int, db: Session = Depends(get_db)):
    """Resume a paused scan.

    Sets the scan status back to 'running'.  The worker detects this and
    sends SIGCONT to the harness process group, unfreezing all child tools.
    """
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "paused":
        raise HTTPException(status_code=400, detail=f"Cannot resume scan in '{scan.status}' state")

    scan.status = "running"

    # Mark paused jobs as running again
    paused_jobs = (
        db.query(ScanJob)
        .filter(
            ScanJob.scan_run_id == scan_id,
            ScanJob.status == "paused",
        )
        .all()
    )
    for job in paused_jobs:
        job.status = "running"

    # Update progress record
    progress = db.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first()
    if progress:
        progress.status = "running"

    db.commit()

    # Emit a log event so the UI stream shows the resume
    db.add(ScanEvent(
        scan_run_id=scan_id,
        event_type="log",
        level="info",
        message="[RESUME] Scan resumed by user",
        created_at=datetime.now(timezone.utc),
    ))
    db.commit()

    return StatusResponse(status="running", message=f"Scan {scan_id} resumed")


@router.get("/{scan_id}/output-data", summary="Get all scan output files bound to UI modules")
def get_output_data(scan_id: int, db: Session = Depends(get_db)):
    """Get all scan output files automatically bound to their corresponding UI modules.

    This endpoint scans the output directory and returns all files organized by
    their target UI modules. Files are automatically routed based on filename
    patterns without requiring manual configuration.

    Returns:
        - modules: Dictionary mapping module names to their files and summaries
        - file_count: Total number of files found
        - module_count: Number of modules with data
        - unrouted_files: Files that didn't match any known pattern
    """
    from app.api.helpers.output_ui_binder import get_dashboard_output_data

    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get all output data bound to UI modules
    output = get_dashboard_output_data(scan.domain, scan_id)

    if not output:
        # No scan output files found
        return {
            "status": "no_output",
            "scan_id": scan_id,
            "domain": scan.domain,
            "message": "No output files found for this scan",
            "modules": {},
            "file_count": 0,
            "module_count": 0,
            "unrouted_files": [],
        }

    return output
