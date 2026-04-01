"""Scan worker — isolated process that pulls work from the job queue.

Architecture
------------
The API server writes a ScanJob row (status='queued') and this worker polls
for it.  Claim is atomic:

  PostgreSQL  — SELECT … FOR UPDATE SKIP LOCKED (no phantom double-claim)
  SQLite      — single UPDATE WHERE id=(SELECT … LIMIT 1) is serialised by
                WAL-mode exclusive write lock

The worker writes ScanEvent rows as the harness produces output so the
SSE stream endpoint delivers real telemetry, not synthetic strings.

Usage
-----
    python -m app.workers.worker           # Persistent polling (auto-restart)
    python -m app.workers.worker --drain   # Process once and exit
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from app.api.middleware.logging import configure_json_logging

_LOG_LEVEL = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
configure_json_logging(level=_LOG_LEVEL)
logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./technieum.db")
WORKER_POLL_SEC = int(os.environ.get("WORKER_POLL_SEC", "5"))
WORKER_MAX_JOBS = int(os.environ.get("WORKER_MAX_JOBS", "4"))  # max concurrent jobs per worker process

# Unique identifier for this worker process instance
_WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

_engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30} if "sqlite" in DATABASE_URL else {},
)

# Enable WAL journal mode for SQLite so the worker's writes don't block
# API server reads.
if "sqlite" in DATABASE_URL:
    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

_Session = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

# Resolve harness path relative to this file: app/workers/ → lib/run_scan.sh
_HARNESS = Path(__file__).resolve().parents[2] / "lib" / "run_scan.sh"

# Output base must match harness: ${TECHNIEUM_OUTPUT_DIR:-./output}
# Resolve relative to repo root (harness parent) so CWD doesn't matter
_REPO_ROOT = Path(__file__).resolve().parents[2]
_OUTPUT_BASE = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(_REPO_ROOT / "output")))

# Nuclei/finding severity string → integer score (matches findings.py convention)
_SEV_MAP = {"critical": 90, "high": 70, "medium": 40, "low": 10, "info": 1}

# Regex for nmap normal-format port lines: "22/tcp   open  ssh      OpenSSH 8.2"
_NMAP_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed|open\|filtered)\s+(\S+)(?:\s+(.+))?$"
)
_NMAP_HOST_RE = re.compile(r"^Nmap scan report for (.+?)(?:\s+\([\d.]+\))?$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _emit_event(
    db: Session,
    scan_run_id: int,
    event_type: str,
    level: str,
    message: str,
    data: Optional[dict] = None,
    phase: Optional[int] = None,
    _commit: bool = True,
) -> None:
    """Persist a ScanEvent row.  Commits immediately by default so the SSE
    stream picks it up without waiting for the scan to finish.
    Pass _commit=False when batching events (caller must call db.commit())."""
    from app.db.models import ScanEvent
    ev = ScanEvent(
        scan_run_id=scan_run_id,
        event_type=event_type,
        level=level,
        message=message,
        data=json.dumps(data) if data else None,
        phase=phase,
        created_at=datetime.now(timezone.utc),
    )
    db.add(ev)
    if _commit:
        db.commit()


def _update_progress(db: Session, scan_run_id: int, **kwargs) -> None:
    """Update ScanProgress fields and commit."""
    from app.db.models import ScanProgress
    prog = db.query(ScanProgress).filter(
        ScanProgress.scan_run_id == scan_run_id
    ).first()
    if prog:
        for k, v in kwargs.items():
            setattr(prog, k, v)
        prog.last_update = datetime.now(timezone.utc)
        db.commit()


# ---------------------------------------------------------------------------
# Atomic job claim — dialect-aware
# ---------------------------------------------------------------------------

def _claim_job(db: Session) -> Optional[object]:
    """Atomically claim one queued ScanJob.  Returns the ORM object or None.

    PostgreSQL: SELECT … FOR UPDATE SKIP LOCKED — zero chance of double-claim
                even with many concurrent workers.
    SQLite:     Single UPDATE inside an implicit transaction; WAL mode allows
                only one writer at a time so the claim is effectively atomic.
    """
    from app.db.models import ScanJob

    dialect = db.get_bind().dialect.name
    now_iso = datetime.now(timezone.utc).isoformat()

    if dialect == "postgresql":
        job = (
            db.query(ScanJob)
            .filter(ScanJob.status == "queued")
            .order_by(ScanJob.id)
            .with_for_update(skip_locked=True)
            .first()
        )
        if job is None:
            return None
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.worker_id = _WORKER_ID
        db.commit()
        return job

    # SQLite path: single UPDATE is atomic under WAL
    result = db.execute(
        text(
            "UPDATE scan_jobs "
            "SET status='running', started_at=:ts, worker_id=:wid "
            "WHERE id = ("
            "  SELECT id FROM scan_jobs WHERE status='queued' ORDER BY id LIMIT 1"
            ")"
        ),
        {"ts": now_iso, "wid": _WORKER_ID},
    )
    db.commit()
    if result.rowcount == 0:
        return None

    # Retrieve the row we just updated (our worker_id is the discriminator)
    job = (
        db.query(ScanJob)
        .filter(ScanJob.worker_id == _WORKER_ID, ScanJob.status == "running")
        .order_by(ScanJob.started_at.desc())
        .first()
    )
    return job


def _finish_job(db: Session, job, success: bool, error: str = "") -> None:
    from app.db.models import ScanJob  # noqa: F811
    job.status = "done" if success else "failed"
    job.finished_at = datetime.now(timezone.utc)
    job.error = error or None
    db.commit()


def _set_scan_status(db: Session, scan_run_id: int, status: str) -> None:
    if status in ("completed", "failed", "stopped"):
        db.execute(
            text("UPDATE scan_runs SET status=:s, completed_at=:t WHERE id=:id"),
            {"s": status, "id": scan_run_id,
             "t": datetime.now(timezone.utc).isoformat()},
        )
    else:
        db.execute(
            text("UPDATE scan_runs SET status=:s WHERE id=:id"),
            {"s": status, "id": scan_run_id},
        )
    db.commit()


# ---------------------------------------------------------------------------
# Result-file parsers
# ---------------------------------------------------------------------------

def _parse_nmap_xml(nmap_xml: Path, scan_run_id: int, sub_map: dict,
                    domain: str, db: Session) -> int:
    """Parse nmap XML output and insert PortScan rows. Returns count inserted."""
    from app.db.models import PortScan
    inserted = 0
    try:
        tree = ET.parse(str(nmap_xml))
        root = tree.getroot()
    except ET.ParseError:
        content = nmap_xml.read_text(errors="ignore")
        if "<nmaprun" in content and "</nmaprun>" not in content:
            content += "\n</nmaprun>"
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return 0
    for host in root.findall("host"):
        hostnames = host.find("hostnames")
        hostname = None
        if hostnames is not None:
            for hn in hostnames.findall("hostname"):
                hostname = hn.get("name")
                break
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue
        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            if state not in ("open", "open|filtered"):
                continue
            port_id = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")
            service_elem = port_elem.find("service")
            service = version = None
            if service_elem is not None:
                service = service_elem.get("name")
                parts = [service_elem.get("product"), service_elem.get("version")]
                version = " ".join(p for p in parts if p) or None
            target_host = hostname or ip or domain
            sub_id = sub_map.get(target_host) or sub_map.get(domain)
            if sub_id is None:
                continue
            db.add(PortScan(
                subdomain_id=sub_id, port=port_id, protocol=protocol,
                state=state, service=service, version=version,
                scanned_at=datetime.now(timezone.utc),
            ))
            inserted += 1
    return inserted


def _parse_nmap_text(nmap_txt: Path, scan_run_id: int, sub_map: dict,
                     domain: str, db: Session) -> int:
    """Parse nmap normal-format text output and insert PortScan rows."""
    from app.db.models import PortScan
    inserted = 0
    current_host = domain
    for raw_line in nmap_txt.read_text(errors="ignore").splitlines():
        line = raw_line.strip()
        m = _NMAP_HOST_RE.match(line)
        if m:
            current_host = m.group(1).strip()
            continue
        m = _NMAP_PORT_RE.match(line)
        if not m:
            continue
        port_id, protocol, state, service, version = (
            int(m.group(1)), m.group(2), m.group(3), m.group(4), m.group(5)
        )
        if state not in ("open", "open|filtered"):
            continue
        sub_id = sub_map.get(current_host) or sub_map.get(domain)
        if sub_id is None:
            continue
        db.add(PortScan(
            subdomain_id=sub_id, port=port_id, protocol=protocol,
            state=state, service=service if service != "unknown" else None,
            version=version.strip() if version else None,
            scanned_at=datetime.now(timezone.utc),
        ))
        inserted += 1
    return inserted


def _parse_nuclei(nuclei_file: Path, scan_run_id: int, sub_map: dict,
                  domain: str, db: Session) -> int:
    """Parse nuclei JSONL *or* JSON array output and insert Vulnerability rows.

    Nuclei >= 3.x outputs one JSON object per line (JSONL).
    Some older/custom configs output a JSON array.  We handle both.
    """
    from app.db.models import Vulnerability
    inserted = 0
    content = nuclei_file.read_text(encoding="utf-8", errors="ignore")

    # Try JSON array first; fall back to JSONL line-by-line
    items: list = []
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            items = [parsed]
    except json.JSONDecodeError:
        for raw in content.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                items.append(json.loads(raw))
            except json.JSONDecodeError:
                continue

    for obj in items:
        info = obj.get("info") or {}
        title = info.get("name") or obj.get("template-id") or "nuclei finding"
        sev_str = (info.get("severity") or "info").lower()
        severity = _SEV_MAP.get(sev_str, 1)
        host_raw = obj.get("host") or obj.get("matched-at") or domain
        host = re.sub(r"^https?://", "", host_raw).split("/")[0].split(":")[0]
        description = (info.get("description") or "")[:2000] or None
        vuln_type = obj.get("template-id") or "nuclei"
        sub_id = sub_map.get(host) or sub_map.get(domain)
        db.add(Vulnerability(
            scan_run_id=scan_run_id,
            subdomain_id=sub_id,
            vuln_type=vuln_type,
            severity=severity,
            title=title[:255],
            description=description,
            discovered_at=datetime.now(timezone.utc),
            status="open",
        ))
        inserted += 1
    return inserted


def _parse_ffuf(ffuf_file: Path) -> int:
    """Parse a single ffuf JSON result file. Returns count of discovered URLs.

    ``ffuf_all.json`` is created with ``jq -s '.'`` which produces a JSON *list*
    of individual ffuf result objects.  Individual per-host files such as
    ``ffuf_example_com.json`` are single JSON *objects* with a ``results`` key.
    Handle both formats gracefully.
    """
    content = ffuf_file.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return 0

    def _count_obj(obj: dict) -> int:
        results = obj.get("results") or [] if isinstance(obj, dict) else []
        return sum(
            1 for r in results
            if isinstance(r, dict) and (
                r.get("url") or (
                    isinstance(r.get("input"), dict) and r["input"].get("FUZZ")
                )
            )
        )

    if isinstance(data, list):
        # ffuf_all.json — jq -s wrapped everything into an array
        return sum(_count_obj(item) for item in data if isinstance(item, dict))
    # Single-host ffuf_<host>.json
    return _count_obj(data)


def _parse_httpx_alive(httpx_file: Path, scan_run_id: int, db: Session) -> int:
    """Parse httpx JSONL output and mark matching Subdomain rows as is_alive=True."""
    from app.db.models import Subdomain
    updated = 0
    content = httpx_file.read_text(encoding="utf-8", errors="ignore")
    for raw in content.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        host_raw = obj.get("host") or obj.get("url") or obj.get("input") or ""
        host = re.sub(r"^https?://", "", host_raw).split("/")[0].split(":")[0].lower()
        if not host:
            continue
        sub = (
            db.query(Subdomain)
            .filter(Subdomain.scan_run_id == scan_run_id, Subdomain.subdomain == host)
            .first()
        )
        if sub and not sub.is_alive:
            sub.is_alive = True
            updated += 1
    if updated:
        db.commit()
    return updated


_FEROX_STATUS_RE = re.compile(r"\b([2-5]\d{2})\b")
_FEROX_URL_RE = re.compile(r"https?://\S+")


def _parse_feroxbuster(ferox_file: Path) -> int:
    """Parse feroxbuster or dirsearch text output. Returns discovered URL count."""
    count = 0
    for raw in ferox_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _FEROX_STATUS_RE.search(line) and _FEROX_URL_RE.search(line):
            count += 1
    return count


def _parse_nikto(nikto_file: Path, scan_run_id: int, sub_map: dict,
                 domain: str, db: Session) -> int:
    """Parse nikto JSON output and insert Vulnerability rows."""
    from app.db.models import Vulnerability
    inserted = 0
    try:
        data = json.loads(nikto_file.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return 0

    # Nikto JSON can be a single object or wrapped in an array
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = [data]
    else:
        return 0

    # ID ranges: 999100–999199=info/misc, 999200+=medium, others vary
    _SEVERITY_BY_ID = {
        "999966": 40,  # BREACH
        "999103": 10,  # missing header (low)
        "999992": 10,  # wildcard cert (low)
    }

    for rec in records:
        host_raw = rec.get("host") or domain
        host = re.sub(r"^https?://", "", str(host_raw)).split("/")[0].split(":")[0].lower()
        sub_id = sub_map.get(host) or sub_map.get(domain)
        for vuln in rec.get("vulnerabilities") or []:
            vid = str(vuln.get("id", ""))
            msg = vuln.get("msg") or vuln.get("description") or ""
            if not msg:
                continue
            severity_score = _SEVERITY_BY_ID.get(vid, 10)
            db.add(Vulnerability(
                scan_run_id=scan_run_id,
                subdomain_id=sub_id,
                vuln_type=f"nikto-{vid}",
                severity=severity_score,
                title=msg[:255],
                description=msg[:2000],
                discovered_at=datetime.now(timezone.utc),
                status="open",
            ))
            inserted += 1
    return inserted


def _ingest_results(scan_run_id: int, domain: str, output_dir: Path,
                    db: Session) -> None:
    """Parse output files from the scan harness and populate the database.

    Each parsing step is independently wrapped in try/except so a failure
    in one file never prevents the others from being ingested.
    """
    from app.db.models import Subdomain

    sub_map: dict[str, int] = {}  # hostname → Subdomain.id

    # ── Subdomains ────────────────────────────────────────────────────────────
    subdomain_file = output_dir / "subdomains.txt"
    if subdomain_file.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing subdomains from {subdomain_file.name}")
            inserted_subs = 0
            for raw in subdomain_file.read_text(errors="ignore").splitlines():
                host = re.sub(r"^https?://", "", raw.strip()).split("/")[0].split(":")[0].lower()
                if not host or " " in host or "." not in host:
                    continue
                existing = db.query(Subdomain).filter(
                    Subdomain.scan_run_id == scan_run_id,
                    Subdomain.subdomain == host,
                ).first()
                if existing:
                    sub_map[host] = existing.id
                    continue
                sub = Subdomain(
                    scan_run_id=scan_run_id,
                    subdomain=host,
                    is_alive=True,
                    discovered_method="enumeration",
                    first_seen=datetime.now(timezone.utc),
                )
                db.add(sub)
                db.flush()
                sub_map[host] = sub.id
                inserted_subs += 1
            db.commit()
            _update_progress(db, scan_run_id, subdomains_found=len(sub_map))
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Subdomains: {inserted_subs} new, {len(sub_map)} total")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Subdomain parse error: {exc}")

    # Ensure target root domain exists in sub_map
    root_sub = db.query(Subdomain).filter(
        Subdomain.scan_run_id == scan_run_id,
        Subdomain.subdomain == domain,
    ).first()
    if root_sub:
        sub_map[domain] = root_sub.id
    elif domain not in sub_map:
        root = Subdomain(
            scan_run_id=scan_run_id, subdomain=domain, is_alive=True,
            discovered_method="enumeration", first_seen=datetime.now(timezone.utc),
        )
        db.add(root)
        db.commit()
        sub_map[domain] = root.id

    # ── Phase 1 Structured Summary (ASN + Cloud + HTTPx details) ─────────────
    p1_summary = next(
        (p for p in [
            output_dir / "phase1_summary.json",
            output_dir / "phase1_discovery" / "phase1_summary.json",
        ] if p.is_file()),
        None,
    )
    if p1_summary is not None:
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing phase1 summary: {p1_summary.name}")
            p1data = json.loads(p1_summary.read_text(encoding="utf-8", errors="ignore"))

            # Emit ASN data as a structured event the UI can render
            asn = p1data.get("asn") or {}
            asn_cidrs = asn.get("cidrs") or []
            asn_ip_count = asn.get("ip_count") or 0
            _emit_event(db, scan_run_id, "asn_data", "info",
                        f"[phase1] ASN: {len(asn_cidrs)} CIDRs, ~{asn_ip_count} IPs",
                        data={
                            "cidrs": asn_cidrs[:200],
                            "ip_count": asn_ip_count,
                            "ips_sample": asn.get("ips_sample") or [],
                        },
                        phase=1)

            # Emit cloud exposure as a structured event
            _ansi_re = re.compile(r'\x1b\[[0-9;]*m')
            def _strip_ansi_list(items):
                return [_ansi_re.sub('', s) if isinstance(s, str) else s for s in items]
            cloud = p1data.get("cloud") or {}
            cloud_total = cloud.get("total") or 0
            if cloud_total:
                _emit_event(db, scan_run_id, "cloud_data", "info",
                            f"[phase1] Cloud: {cloud_total} assets found "
                            f"(AWS:{len(cloud.get('aws') or [])}, "
                            f"Azure:{len(cloud.get('azure') or [])}, "
                            f"GCP:{len(cloud.get('gcp') or [])})",
                            data={
                                "total": cloud_total,
                                "assets": _strip_ansi_list((cloud.get("assets") or [])[:200]),
                                "aws":    _strip_ansi_list(cloud.get("aws") or []),
                                "azure":  _strip_ansi_list(cloud.get("azure") or []),
                                "gcp":    _strip_ansi_list(cloud.get("gcp") or []),
                            },
                            phase=1)
            else:
                _emit_event(db, scan_run_id, "cloud_data", "info",
                            "[phase1] Cloud: no cloud assets detected",
                            data={"total": 0, "assets": [], "aws": [], "azure": [], "gcp": []},
                            phase=1)

            # Emit CT (certificate transparency) stats
            ct = p1data.get("ct_sources") or {}
            if ct:
                _emit_event(db, scan_run_id, "ct_data", "info",
                            f"[phase1] CT logs: certspotter={ct.get('certspotter',0)}, crt.sh={ct.get('crtsh',0)}",
                            data=ct, phase=1)

            # Emit alive_urls for downstream UI display
            alive_urls = p1data.get("alive_urls") or []
            if alive_urls:
                _emit_event(db, scan_run_id, "alive_hosts", "info",
                            f"[phase1] Live hosts: {len(alive_urls)} URLs responsive",
                            data={"urls": alive_urls[:500], "count": len(alive_urls)},
                            phase=1)

            # Emit HTTPx details as structured event for discovered-assets table
            httpx_details = p1data.get("httpx_details") or []
            if httpx_details:
                _update_progress(db, scan_run_id, subdomains_found=p1data.get("subdomain_count") or 0)
                _emit_event(db, scan_run_id, "httpx_details", "info",
                            f"[phase1] HTTPx: {len(httpx_details)} host details",
                            data={"hosts": httpx_details[:500]},
                            phase=1)

            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Phase1 summary: subs={p1data.get('subdomain_count',0)}, "
                        f"alive={p1data.get('alive_count',0)}, "
                        f"cloud={cloud_total}, asn_cidrs={len(asn_cidrs)}")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Phase1 summary parse error: {exc}")

    # ── Ports (nmap) ─────────────────────────────────────────────────────────
    # Check root dir first, then phase2_intel/ports/ subdirectory
    nmap_xml = next(
        (p for p in [
            output_dir / "nmap.xml",
            output_dir / "phase2_intel" / "ports" / "nmap_all.xml",
            output_dir / "phase2_intel" / "ports" / "nmap.xml",
        ] if p.is_file()),
        None,
    )
    nmap_txt = next(
        (p for p in [
            output_dir / "nmap.txt",
            output_dir / "phase2_intel" / "ports" / "nmap_all.txt",
            output_dir / "phase2_intel" / "ports" / "nmap.txt",
        ] if p.is_file()),
        None,
    )
    ports_inserted = 0
    if nmap_xml is not None:
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing nmap XML: {nmap_xml}")
            ports_inserted = _parse_nmap_xml(nmap_xml, scan_run_id, sub_map, domain, db)
            db.commit()
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Nmap XML parse error: {exc}")
    elif nmap_txt is not None:
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing nmap text: {nmap_txt}")
            ports_inserted = _parse_nmap_text(nmap_txt, scan_run_id, sub_map, domain, db)
            db.commit()
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Nmap text parse error: {exc}")
    if ports_inserted:
        _update_progress(db, scan_run_id, ports_found=ports_inserted)
        _emit_event(db, scan_run_id, "log", "info",
                    f"[ingestion] Ports: {ports_inserted} inserted")

    # ── Vulnerabilities (nuclei) ──────────────────────────────────────────────────
    # Check root dir and phase4 subdirectories
    _nuclei_dir = output_dir / "phase4_vulnscan" / "nuclei"
    _extra_nuclei = list(_nuclei_dir.glob("*.json")) if _nuclei_dir.is_dir() else []
    nuclei_candidates = [
        output_dir / "nuclei.json",
        output_dir / "nuclei_results.json",
        output_dir / "phase4_vulnscan" / "nuclei" / "nuclei_results.json",
        output_dir / "phase4_vulnscan" / "nuclei" / "nuclei.json",
    ] + _extra_nuclei
    for nuclei_file in nuclei_candidates:
        if not nuclei_file.is_file():
            continue
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing nuclei results: {nuclei_file}")
            vulns_inserted = _parse_nuclei(nuclei_file, scan_run_id, sub_map, domain, db)
            db.commit()
            if vulns_inserted:
                _update_progress(db, scan_run_id, vulnerabilities_found=vulns_inserted)
                _emit_event(db, scan_run_id, "log", "info",
                            f"[ingestion] Findings: {vulns_inserted} inserted")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Nuclei parse error: {exc}")
        break  # only process first matching file

    # ── Nikto vulnerability findings ─────────────────────────────────────────
    nikto_dir = output_dir / "phase4_vulnscan" / "misc"
    if nikto_dir.is_dir():
        for nikto_file in nikto_dir.glob("nikto_*.json"):
            try:
                n_inserted = _parse_nikto(nikto_file, scan_run_id, sub_map, domain, db)
                if n_inserted:
                    db.commit()
                    _emit_event(db, scan_run_id, "log", "info",
                                f"[ingestion] Nikto: {n_inserted} findings from {nikto_file.name}")
            except Exception as exc:
                db.rollback()
                _emit_event(db, scan_run_id, "log", "warning",
                            f"[ingestion] Nikto parse error ({nikto_file.name}): {exc}")
        # Total vuln count update
        from app.db.models import Vulnerability as _VN
        total_vulns = db.query(_VN).filter(_VN.scan_run_id == scan_run_id).count()
        if total_vulns:
            _update_progress(db, scan_run_id, vulnerabilities_found=total_vulns)

    # ── FFUF results (each file individually) ────────────────────────────────
    # FFUF files live in phase3_content/bruteforce/ but ffuf_all.json may also
    # be copied to the output root by run_scan.sh.  Search both locations and
    # deduplicate by resolved path so we don't double-count.
    _ffuf_seen: set = set()
    _ffuf_files = list(output_dir.glob("ffuf_*.json"))
    _ffuf_files += list((output_dir / "phase3_content" / "bruteforce").glob("ffuf_*.json"))
    for ffuf_file in _ffuf_files:
        _ffuf_key = ffuf_file.resolve()
        if _ffuf_key in _ffuf_seen:
            continue
        _ffuf_seen.add(_ffuf_key)
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing ffuf: {ffuf_file.name}")
            count = _parse_ffuf(ffuf_file)
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] FFUF: {count} URLs in {ffuf_file.name}")
        except Exception as exc:
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] FFUF parse error ({ffuf_file.name}): {exc}")

    # ── HTTPx / SubProber alive results ──────────────────────────────────────
    for httpx_file in [output_dir / "httpx_alive.json", *output_dir.glob("subprober_*.json")]:
        if not httpx_file.is_file():
            continue
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing HTTPx alive: {httpx_file.name}")
            count = _parse_httpx_alive(httpx_file, scan_run_id, db)
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] HTTPx: {count} subdomains marked alive")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] HTTPx parse error ({httpx_file.name}): {exc}")

    # ── Feroxbuster / Dirsearch discovered URLs ───────────────────────────────
    for ferox_file in [*output_dir.glob("feroxbuster_*.txt"), *output_dir.glob("dirsearch_*.txt")]:
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing directory brute: {ferox_file.name}")
            count = _parse_feroxbuster(ferox_file)
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Dir brute: {count} URLs in {ferox_file.name}")
        except Exception as exc:
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Feroxbuster parse error ({ferox_file.name}): {exc}")

    # ── Phase 5: Threat Intelligence ─────────────────────────────────────────
    threat_file = output_dir / "threat_intel_summary.json"
    if threat_file.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        "[ingestion] Parsing threat intel summary")
            data = json.loads(threat_file.read_text(encoding="utf-8", errors="ignore"))
            from app.db.models import ThreatIntelData, MalwareIndicator, DataLeak
            inserted_ti = 0

            # Threat indicators (ip_reputation, domain_reputation, blocklists)
            for section_key in ("ip_reputation", "domain_reputation", "blocklists",
                                "indicators", "threat_indicators"):
                items = data.get(section_key, [])
                if isinstance(items, dict):
                    items = [items]
                for item in (items if isinstance(items, list) else []):
                    if not isinstance(item, dict):
                        continue
                    ind_type = item.get("type") or item.get("indicator_type") or section_key
                    ind_val = item.get("value") or item.get("indicator") or item.get("ip") or item.get("domain") or ""
                    if not ind_val:
                        continue
                    sev_raw = item.get("severity") or item.get("risk_score") or item.get("confidence_score")
                    sev = int(sev_raw) if sev_raw and str(sev_raw).isdigit() else None
                    db.add(ThreatIntelData(
                        indicator_type=str(ind_type)[:50],
                        indicator_value=str(ind_val)[:500],
                        severity=sev,
                        source=str(item.get("source", "phase5"))[:100],
                        description=str(item.get("description", ""))[:2000] or None,
                    ))
                    inserted_ti += 1

            # Malware indicators (urlhaus, threatfox)
            for mk in ("malware", "urlhaus", "threatfox", "malware_indicators"):
                items = data.get(mk, [])
                if isinstance(items, dict):
                    items = [items]
                for item in (items if isinstance(items, list) else []):
                    if not isinstance(item, dict):
                        continue
                    ind_val = item.get("ioc") or item.get("url") or item.get("indicator") or item.get("value") or ""
                    if not ind_val:
                        continue
                    db.add(MalwareIndicator(
                        scan_run_id=scan_run_id,
                        indicator_type=str(item.get("type", item.get("ioc_type", "url")))[:50],
                        indicator_value=str(ind_val)[:500],
                        malware_family=str(item.get("malware_family", item.get("family", "")))[:100] or None,
                        verdict=str(item.get("verdict", item.get("threat_type", "")))[:50] or None,
                        analyzed_by=str(item.get("source", mk))[:100],
                    ))
                    inserted_ti += 1

            # Data leaks / breach data
            for lk in ("data_leaks", "breaches", "breach_monitoring"):
                items = data.get(lk, [])
                if isinstance(items, dict):
                    items = [items]
                for item in (items if isinstance(items, list) else []):
                    if not isinstance(item, dict):
                        continue
                    email = item.get("email") or item.get("identity") or ""
                    breach = item.get("breach_name") or item.get("source") or item.get("name") or "unknown"
                    if not email:
                        continue
                    db.add(DataLeak(
                        scan_run_id=scan_run_id,
                        email=str(email)[:255],
                        breach_name=str(breach)[:255],
                        exposed_data=str(item.get("exposed_data", ""))[:500] or None,
                        source_url=str(item.get("source_url", ""))[:500] or None,
                    ))
                    inserted_ti += 1

            db.commit()
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Threat intel: {inserted_ti} records inserted")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Threat intel parse error: {exc}")

    # ── Phase 6: CVE Correlation & Risk Scores ───────────────────────────────
    risk_file = output_dir / "risk_summary.json"
    cve_file = output_dir / "cve_matches.json"
    if risk_file.is_file() or cve_file.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        "[ingestion] Parsing CVE correlation / risk scores")
            from app.db.models import RiskScore, VulnerabilityMetadata

            # Risk summary → RiskScore table + ScanRun.risk_score
            if risk_file.is_file():
                rdata = json.loads(risk_file.read_text(encoding="utf-8", errors="ignore"))
                crit = int(rdata.get("critical_count", rdata.get("critical", 0)) or 0)
                high = int(rdata.get("high_count", rdata.get("high", 0)) or 0)
                med = int(rdata.get("medium_count", rdata.get("medium", 0)) or 0)
                low = int(rdata.get("low_count", rdata.get("low", 0)) or 0)
                overall = int(rdata.get("overall_score", rdata.get("risk_score", 0)) or 0)
                if overall == 0:
                    overall = min(100, crit * 20 + high * 10 + med * 3 + low)
                db.add(RiskScore(
                    scan_run_id=scan_run_id,
                    calculation_method=str(rdata.get("method", "weighted"))[:50],
                    critical_count=crit,
                    high_count=high,
                    medium_count=med,
                    low_count=low,
                    overall_score=overall,
                ))
                # Also update scan_run.risk_score for the scans list UI
                db.execute(
                    text("UPDATE scan_runs SET risk_score=:s WHERE id=:id"),
                    {"s": overall, "id": scan_run_id},
                )
                db.commit()
                _emit_event(db, scan_run_id, "log", "info",
                            f"[ingestion] Risk score: {overall} (C:{crit} H:{high} M:{med} L:{low})")

            # CVE matches → VulnerabilityMetadata on existing Vulnerability rows
            if cve_file.is_file():
                cdata = json.loads(cve_file.read_text(encoding="utf-8", errors="ignore"))
                cve_items = cdata if isinstance(cdata, list) else cdata.get("matches", cdata.get("cves", []))
                enriched = 0
                for item in (cve_items if isinstance(cve_items, list) else []):
                    if not isinstance(item, dict):
                        continue
                    cve_id = item.get("cve_id") or item.get("id") or ""
                    if not cve_id:
                        continue
                    # Try to find matching vulnerability by CVE in title/cve_ids
                    from app.db.models import Vulnerability
                    vuln = db.query(Vulnerability).filter(
                        Vulnerability.scan_run_id == scan_run_id,
                        Vulnerability.cve_ids.like(f"%{cve_id}%"),
                    ).first()
                    if not vuln:
                        vuln = db.query(Vulnerability).filter(
                            Vulnerability.scan_run_id == scan_run_id,
                            Vulnerability.title.like(f"%{cve_id}%"),
                        ).first()
                    vuln_id = vuln.id if vuln else None
                    db.add(VulnerabilityMetadata(
                        vulnerability_id=vuln_id,
                        cve_id=str(cve_id)[:50],
                        cvss_v31_score=float(item.get("cvss", item.get("cvss_score", 0)) or 0) or None,
                        cvss_v31_vector=str(item.get("cvss_vector", ""))[:100] or None,
                        epss_score=float(item.get("epss", item.get("epss_score", 0)) or 0) or None,
                        in_kev=bool(item.get("in_kev", item.get("kev", False))),
                        has_metasploit=bool(item.get("has_metasploit", False)),
                        active_exploitation=bool(item.get("active_exploitation", item.get("in_kev", False))),
                        source=str(item.get("source", "phase6_cve"))[:100],
                    ))
                    enriched += 1
                db.commit()
                _emit_event(db, scan_run_id, "log", "info",
                            f"[ingestion] CVE enrichment: {enriched} records")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] CVE/risk parse error: {exc}")

    # ── Phase 7: Change Detection ────────────────────────────────────────────
    change_file = output_dir / "change_detection_summary.json"
    delta_file = output_dir / "change_delta.json"
    if change_file.is_file() or delta_file.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        "[ingestion] Parsing change detection data")
            from app.db.models import AssetSnapshot, BaselineSnapshot

            # Create current asset snapshot
            from app.db.models import Subdomain as _Sub, PortScan as _PS, Vulnerability as _V
            sub_count = db.query(_Sub).filter(_Sub.scan_run_id == scan_run_id).count()
            port_count = db.query(_PS).join(_Sub).filter(_Sub.scan_run_id == scan_run_id).count()
            vuln_count = db.query(_V).filter(_V.scan_run_id == scan_run_id).count()
            crit_count = db.query(_V).filter(
                _V.scan_run_id == scan_run_id, _V.severity >= 90
            ).count()

            snapshot = AssetSnapshot(
                scan_run_id=scan_run_id,
                domain_count=1,
                subdomain_count=sub_count,
                open_port_count=port_count,
                vulnerability_count=vuln_count,
                critical_vuln_count=crit_count,
            )
            db.add(snapshot)
            db.flush()

            # Create baseline snapshot with change data
            snap_data = {}
            if change_file.is_file():
                snap_data = json.loads(change_file.read_text(encoding="utf-8", errors="ignore"))
            elif delta_file.is_file():
                snap_data = json.loads(delta_file.read_text(encoding="utf-8", errors="ignore"))

            db.add(BaselineSnapshot(
                scan_run_id=scan_run_id,
                is_baseline=True,
                asset_count=sub_count + port_count,
                subdomain_count=sub_count,
                port_count=port_count,
                vulnerability_count=vuln_count,
                risk_score_snapshot=snap_data.get("risk_score", 0) or 0,
                snapshot_data=json.dumps(snap_data)[:4000] if snap_data else None,
            ))
            db.commit()
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Change detection: snapshot created "
                        f"(subs={sub_count}, ports={port_count}, vulns={vuln_count})")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Change detection parse error: {exc}")

    # ── Phase 8: Compliance ──────────────────────────────────────────────────
    compliance_file = output_dir / "compliance_summary.json"
    if compliance_file.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        "[ingestion] Parsing compliance summary")
            from app.db.models import ComplianceReport, ComplianceFinding
            cdata = json.loads(compliance_file.read_text(encoding="utf-8", errors="ignore"))

            # Process each framework in the compliance summary
            frameworks = cdata.get("frameworks", cdata.get("reports", []))
            if isinstance(frameworks, dict):
                frameworks = [{"framework": k, **v} for k, v in frameworks.items()]
            if not frameworks and isinstance(cdata, dict):
                # Might be a single-framework report
                if cdata.get("framework") or cdata.get("report_type"):
                    frameworks = [cdata]

            inserted_cr = 0
            for fw in (frameworks if isinstance(frameworks, list) else []):
                if not isinstance(fw, dict):
                    continue
                fw_name = fw.get("framework") or fw.get("report_type") or fw.get("name") or "compliance"
                passed = int(fw.get("passed_checks", fw.get("passed", 0)) or 0)
                failed = int(fw.get("failed_checks", fw.get("failed", 0)) or 0)
                score = fw.get("overall_score") or fw.get("score")
                if score is not None:
                    score = int(score)
                elif passed + failed > 0:
                    score = int((passed / (passed + failed)) * 100)

                report = ComplianceReport(
                    scan_run_id=scan_run_id,
                    report_type=str(fw_name)[:50],
                    passed_checks=passed,
                    failed_checks=failed,
                    overall_score=score,
                )
                db.add(report)
                db.flush()

                # Add individual findings
                findings = fw.get("findings") or fw.get("checks") or fw.get("controls") or []
                for finding in (findings if isinstance(findings, list) else []):
                    if not isinstance(finding, dict):
                        continue
                    db.add(ComplianceFinding(
                        report_id=report.id,
                        requirement_id=str(finding.get("requirement_id", finding.get("id", f"REQ-{inserted_cr}")))[:50],
                        control_name=str(finding.get("control_name", finding.get("name", finding.get("title", "Unknown"))))[:255],
                        status=str(finding.get("status", "unknown"))[:20],
                        evidence=str(finding.get("evidence", ""))[:4000] or None,
                        remediation=str(finding.get("remediation", ""))[:4000] or None,
                        severity=str(finding.get("severity", ""))[:20] or None,
                    ))
                inserted_cr += 1

            db.commit()
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Compliance: {inserted_cr} framework reports inserted")
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Compliance parse error: {exc}")

    # ── Phase 9: Attack Graph ────────────────────────────────────────────────
    ag_summary = output_dir / "attack_graph_summary.json"
    if ag_summary.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        "[ingestion] Parsing attack graph summary")
            agdata = json.loads(ag_summary.read_text(encoding="utf-8", errors="ignore"))
            nodes = agdata.get("graph_nodes", 0)
            edges = agdata.get("graph_edges", 0)
            entry_pts = agdata.get("entry_points", 0)
            attack_paths = agdata.get("attack_paths", 0)
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Attack graph: {nodes} nodes, {edges} edges, "
                        f"{entry_pts} entry points, {attack_paths} attack paths",
                        data=agdata)
        except Exception as exc:
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Attack graph parse error: {exc}")

    # ── Final: Compute risk score if not set ─────────────────────────────────
    try:
        row = db.execute(
            text("SELECT risk_score FROM scan_runs WHERE id=:id"),
            {"id": scan_run_id},
        ).fetchone()
        if row and not row[0]:
            from app.db.models import Vulnerability as _V2
            vulns = db.query(_V2).filter(_V2.scan_run_id == scan_run_id).all()
            crit = sum(1 for v in vulns if (v.severity or 0) >= 90)
            high = sum(1 for v in vulns if 70 <= (v.severity or 0) < 90)
            med = sum(1 for v in vulns if 40 <= (v.severity or 0) < 70)
            low = sum(1 for v in vulns if 1 <= (v.severity or 0) < 40)
            score = min(100, crit * 20 + high * 10 + med * 3 + low)
            if score > 0:
                db.execute(
                    text("UPDATE scan_runs SET risk_score=:s WHERE id=:id"),
                    {"s": score, "id": scan_run_id},
                )
                db.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Scan execution (Blocker B — fail hard if harness absent)
# ---------------------------------------------------------------------------

def _run_scan(scan_run_id: int, db: Session) -> tuple[bool, str]:
    """Execute the scan harness, stream output as ScanEvents, return (ok, err).

    Raises FileNotFoundError if the harness script is missing — the worker
    must not silently succeed when the execution path is invalid.
    """
    if not _HARNESS.is_file():
        raise FileNotFoundError(
            f"Scan harness not found at {_HARNESS}. "
            "Ensure lib/run_scan.sh exists and is executable."
        )
    if not os.access(_HARNESS, os.X_OK):
        _HARNESS.chmod(0o755)

    # Fetch scan metadata
    row = db.execute(
        text("SELECT domain, scan_type FROM scan_runs WHERE id=:id"),
        {"id": scan_run_id},
    ).fetchone()
    if row is None:
        return False, f"scan_run {scan_run_id} not found"
    domain, scan_type = row

    _emit_event(
        db, scan_run_id, "log", "info",
        f"Starting scan for {domain} (type={scan_type or 'full'}, "
        f"worker={_WORKER_ID})"
    )
    _update_progress(db, scan_run_id, status="running", current_phase=0,
                     progress_percentage=5)

    try:
        proc = subprocess.Popen(
            [str(_HARNESS), str(scan_run_id), domain, scan_type or "full"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr so we capture everything
            stdin=subprocess.DEVNULL,  # prevent terminal stdin inheritance (avoids SIGTTIN stopping sub-tools)
            text=True,
            bufsize=1,  # line-buffered
            cwd=str(_REPO_ROOT),  # match harness ./output relative path
            start_new_session=True,  # detach from controlling terminal (prevents SIGTTOU/SIGTTIN on sub-processes)
        )

        # Batch event writes — commit every _BATCH_SIZE lines or every
        # _BATCH_SECS seconds to reduce SQLite write-lock contention.
        # The API server (and SSE stream) can then read between commits.
        _BATCH_SIZE = 10
        _BATCH_SECS = 2.0
        _batch_count = 0
        _last_commit = time.monotonic()
        _is_paused = False  # track pause state to avoid repeated SIGSTOP/SIGCONT

        for raw_line in proc.stdout:
            # Check if scan was stopped or paused via API while running
            current = db.execute(
                text("SELECT status FROM scan_runs WHERE id=:id"),
                {"id": scan_run_id},
            ).fetchone()
            if current and current[0] in ("stopped", "failed"):
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                db.commit()  # flush any pending batch
                return False, f"scan {current[0]} by request"

            # Handle pause: send SIGSTOP to process group, then poll DB
            # until status changes back to 'running' (resume) or 'stopped'.
            if current and current[0] == "paused" and not _is_paused:
                _is_paused = True
                try:
                    import signal
                    os.killpg(os.getpgid(proc.pid), signal.SIGSTOP)
                    logger.info("scan paused", extra={"scan_run_id": scan_run_id})
                except Exception as pause_exc:
                    logger.warning(f"SIGSTOP failed (non-fatal): {pause_exc}")

                # Flush any pending batch before entering pause loop
                if _batch_count > 0:
                    db.commit()
                    _batch_count = 0
                    _last_commit = time.monotonic()

                # Poll every 3 seconds until resumed or stopped
                while True:
                    time.sleep(3)
                    poll_status = db.execute(
                        text("SELECT status FROM scan_runs WHERE id=:id"),
                        {"id": scan_run_id},
                    ).fetchone()
                    if poll_status and poll_status[0] == "running":
                        # Resumed — send SIGCONT
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
                            logger.info("scan resumed", extra={"scan_run_id": scan_run_id})
                        except Exception as resume_exc:
                            logger.warning(f"SIGCONT failed (non-fatal): {resume_exc}")
                        _is_paused = False
                        break
                    elif poll_status and poll_status[0] in ("stopped", "failed"):
                        # Stopped while paused — unfreeze then terminate
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGCONT)
                            time.sleep(0.1)
                            proc.terminate()
                            proc.wait(timeout=10)
                        except Exception:
                            try:
                                proc.kill()
                                proc.wait()
                            except Exception:
                                pass
                        return False, f"scan {poll_status[0]} while paused"
                    # else: still paused, keep polling
                continue  # re-read from stdout after resume

            line = raw_line.rstrip()
            if not line:
                continue

            # Skip raw JSON blobs from tools (ffuf, nuclei etc.) — they are
            # ingested separately from output files; storing them as events
            # floods scan_events with hundreds of JSON rows and causes
            # false-positive errors (FUZZ words like "errorpage" trigger
            # the old fuzzy level detector).
            stripped = line.lstrip()
            if stripped.startswith(("{", "[")):
                continue

            # Parse phase hints from harness output e.g. "[phase:2]"
            phase = None
            if "[phase:" in line:
                try:
                    phase = int(line.split("[phase:")[1].split("]")[0])
                    pct = min(10 + phase * 20, 90)
                    _update_progress(db, scan_run_id, current_phase=phase,
                                     progress_percentage=pct)
                    _batch_count += 1
                except (ValueError, IndexError):
                    pass

            # Use explicit bracket markers only — avoids false positives from
            # tool output that contains the words "error"/"warn" naturally
            # (e.g. amass libpostal messages, FFUF FUZZ wordlist entries).
            if "[ERROR]" in line or "[CRITICAL]" in line or "[FATAL]" in line:
                level = "error"
            elif "[WARN]" in line or "[WARNING]" in line:
                level = "warning"
            else:
                level = "info"

            _emit_event(db, scan_run_id, "log", level, line, phase=phase,
                        _commit=False)
            _batch_count += 1

            # Flush batch to DB on size or time threshold
            now = time.monotonic()
            if _batch_count >= _BATCH_SIZE or (now - _last_commit) >= _BATCH_SECS:
                db.commit()
                _batch_count = 0
                _last_commit = now

        # Flush any remaining buffered events
        if _batch_count > 0:
            db.commit()

        try:
            proc.wait(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return False, "scan timed out after 3600 seconds"

        if proc.returncode != 0:
            return False, f"harness exited with code {proc.returncode}"

        # Ingest output files — failures are non-fatal so wrap tightly
        output_dir = _OUTPUT_BASE / f"{domain.replace('.', '_')}_scan_{scan_run_id}"
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Starting result ingestion from {output_dir}")
            _ingest_results(scan_run_id, domain, output_dir, db)
            _emit_event(db, scan_run_id, "log", "info",
                        "[ingestion] Result ingestion complete")
        except Exception as ingest_exc:
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Non-fatal ingestion error: {ingest_exc}")

        _update_progress(db, scan_run_id, status="done", progress_percentage=100)
        _emit_event(db, scan_run_id, "completed", "info",
                    f"Scan finished: domain={domain}")
        return True, ""

    except FileNotFoundError:
        raise  # propagate — do not swallow
    except Exception as exc:
        return False, str(exc)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_once(db: Optional[Session] = None) -> int:
    """Claim and execute all currently queued jobs.  Returns jobs processed."""
    own_session = db is None
    if own_session:
        db = _Session()

    processed = 0
    try:
        while processed < WORKER_MAX_JOBS:
            job = _claim_job(db)
            if job is None:
                break

            scan_run_id = job.scan_run_id
            logger.info(
                "job claimed",
                extra={"job_id": job.id, "scan_run_id": scan_run_id,
                       "worker": _WORKER_ID},
            )
            _set_scan_status(db, scan_run_id, "running")

            try:
                success, error = _run_scan(scan_run_id, db)
            except FileNotFoundError as exc:
                success = False
                error = str(exc)
                logger.error(
                    "harness missing — aborting job",
                    extra={"job_id": job.id, "error": error},
                )

            _finish_job(db, job, success, error)
            # Do not overwrite a stopped status that was set via /stop endpoint
            current_status_row = db.execute(
                text("SELECT status FROM scan_runs WHERE id=:id"),
                {"id": scan_run_id},
            ).fetchone()
            if current_status_row and current_status_row[0] not in ("stopped",):
                final_status = "completed" if success else "failed"
                _set_scan_status(db, scan_run_id, final_status)

            if not success:
                _emit_event(db, scan_run_id, "error", "error",
                            f"Scan failed: {error}")
                _update_progress(db, scan_run_id, status="failed")

            logger.info(
                "job finished",
                extra={"job_id": job.id, "scan_run_id": scan_run_id,
                       "success": success},
            )
            processed += 1

    finally:
        if own_session:
            try:
                db.rollback()  # ensure any pending/broken transaction is cleared
            except Exception:
                pass
            db.close()

    return processed


def _recover_orphaned_jobs() -> int:
    """Reset scan_jobs stuck in 'running' from a previously crashed worker.

    Any job with status='running' and a worker_id different from this process
    that started more than 30 minutes ago is considered orphaned (the worker
    process that claimed it is no longer alive).  Resetting it to 'queued'
    allows this worker (or any future worker) to pick it up and run it.
    """
    from datetime import timedelta
    db = _Session()
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        res = db.execute(
            text(
                "UPDATE scan_jobs"
                " SET status='queued', worker_id=NULL, started_at=NULL"
                " WHERE status='running'"
                " AND worker_id IS NOT NULL"
                " AND worker_id != :wid"
                " AND (started_at IS NULL OR started_at < :cutoff)"
            ),
            {"wid": _WORKER_ID, "cutoff": cutoff},
        )
        n = res.rowcount
        if n > 0:
            # Also reset the corresponding scan_run rows so the worker can
            # update their status correctly when re-processing.
            db.execute(
                text(
                    "UPDATE scan_runs SET status='queued', completed_at=NULL"
                    " WHERE status='running'"
                    " AND id IN ("
                    "   SELECT scan_run_id FROM scan_jobs WHERE status='queued' AND worker_id IS NULL"
                    " )"
                )
            )
            db.commit()
            logger.info(
                f"Recovered {n} orphaned job(s) from crashed workers — re-queued for processing"
            )
        return n
    except Exception as exc:
        logger.warning(f"Orphan recovery failed (non-fatal): {exc}")
        db.rollback()
        return 0
    finally:
        db.close()


def run_forever() -> None:
    """Poll the queue indefinitely; auto-restart on unhandled errors."""
    logger.info("worker started", extra={"worker_id": _WORKER_ID,
                                          "poll_sec": WORKER_POLL_SEC})
    # Recover any jobs left 'running' by a previous crashed worker process so
    # they are picked up and completed rather than orphaned forever.
    _recover_orphaned_jobs()
    while True:
        try:
            n = run_once()
            if n == 0:
                time.sleep(WORKER_POLL_SEC)
        except KeyboardInterrupt:
            logger.info("worker stopping")
            sys.exit(0)
        except Exception as exc:
            logger.error("worker error — will retry",
                         extra={"error": str(exc)})
            # Dispose the connection pool so the next run_once() gets fresh
            # connections — prevents "Can't reconnect until invalid transaction
            # is rolled back" (SQLAlchemy error 8s2b) from persisting.
            try:
                _engine.dispose()
            except Exception:
                pass
            time.sleep(WORKER_POLL_SEC)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Technieum scan worker")
    parser.add_argument(
        "--drain", action="store_true",
        help="Process all queued jobs once then exit"
    )
    args = parser.parse_args()
    if args.drain:
        n = run_once()
        print(f"Processed {n} job(s).")
    else:
        run_forever()
