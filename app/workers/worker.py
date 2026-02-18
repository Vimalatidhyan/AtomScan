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

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./reconx.db")
WORKER_POLL_SEC = int(os.environ.get("WORKER_POLL_SEC", "5"))
WORKER_MAX_JOBS = int(os.environ.get("WORKER_MAX_JOBS", "4"))  # max concurrent jobs per worker process

# Unique identifier for this worker process instance
_WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

_engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
_Session = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

# Resolve harness path relative to this file: app/workers/ → lib/run_scan.sh
_HARNESS = Path(__file__).resolve().parents[2] / "lib" / "run_scan.sh"

# Output base must match harness: ${RECONX_OUTPUT_DIR:-./output}
# Resolve relative to repo root (harness parent) so CWD doesn't matter
_REPO_ROOT = Path(__file__).resolve().parents[2]
_OUTPUT_BASE = Path(os.environ.get("RECONX_OUTPUT_DIR", str(_REPO_ROOT / "output")))

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
) -> None:
    """Persist a ScanEvent row.  Each call commits immediately so the SSE
    stream picks it up without waiting for the scan to finish."""
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
    tree = ET.parse(str(nmap_xml))
    root = tree.getroot()
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
    """Parse a single ffuf JSON result file. Returns count of discovered URLs."""
    content = ffuf_file.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return 0
    results = data.get("results") or []
    count = 0
    for item in results:
        if item.get("url") or item.get("input", {}).get("FUZZ"):
            count += 1
    return count


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

    # ── Ports (nmap) ─────────────────────────────────────────────────────────
    nmap_xml = output_dir / "nmap.xml"
    nmap_txt = output_dir / "nmap.txt"
    ports_inserted = 0
    if nmap_xml.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing nmap XML: {nmap_xml.name}")
            ports_inserted = _parse_nmap_xml(nmap_xml, scan_run_id, sub_map, domain, db)
            db.commit()
        except Exception as exc:
            db.rollback()
            _emit_event(db, scan_run_id, "log", "warning",
                        f"[ingestion] Nmap XML parse error: {exc}")
    elif nmap_txt.is_file():
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing nmap text: {nmap_txt.name}")
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

    # ── Vulnerabilities (nuclei) ──────────────────────────────────────────────
    for nuclei_file in (output_dir / "nuclei.json", output_dir / "nuclei_results.json"):
        if not nuclei_file.is_file():
            continue
        try:
            _emit_event(db, scan_run_id, "log", "info",
                        f"[ingestion] Parsing nuclei results: {nuclei_file.name}")
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

    # ── FFUF results (each file individually) ────────────────────────────────
    for ffuf_file in output_dir.glob("ffuf_*.json"):
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
            text=True,
            bufsize=1,  # line-buffered
            cwd=str(_REPO_ROOT),  # match harness ./output relative path
        )

        for raw_line in proc.stdout:
            # Check if scan was stopped via API while running
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
                return False, f"scan {current[0]} by request"

            line = raw_line.rstrip()
            if not line:
                continue

            # Parse phase hints from harness output e.g. "[phase:2]"
            phase = None
            if "[phase:" in line:
                try:
                    phase = int(line.split("[phase:")[1].split("]")[0])
                    pct = min(10 + phase * 20, 90)
                    _update_progress(db, scan_run_id, current_phase=phase,
                                     progress_percentage=pct)
                except (ValueError, IndexError):
                    pass

            level = "warning" if "[WARN]" in line or "warn" in line.lower() else "info"
            if "[ERROR]" in line or "error" in line.lower():
                level = "error"

            _emit_event(db, scan_run_id, "log", level, line, phase=phase)

        try:
            proc.wait(timeout=3600)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return False, "scan timed out after 3600 seconds"

        if proc.returncode != 0:
            return False, f"harness exited with code {proc.returncode}"

        # Ingest output files — failures are non-fatal so wrap tightly
        output_dir = _OUTPUT_BASE / f"{domain.replace('.', '_')}_{scan_run_id}"
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
            db.close()

    return processed


def run_forever() -> None:
    """Poll the queue indefinitely; auto-restart on unhandled errors."""
    logger.info("worker started", extra={"worker_id": _WORKER_ID,
                                          "poll_sec": WORKER_POLL_SEC})
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
            time.sleep(WORKER_POLL_SEC)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReconX scan worker")
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
