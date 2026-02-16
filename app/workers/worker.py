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
import socket
import subprocess
import sys
import time
import uuid
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

# Unique identifier for this worker process instance
_WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

_engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)
_Session = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

# Resolve harness path relative to this file: app/workers/ → lib/run_scan.sh
_HARNESS = Path(__file__).resolve().parents[2] / "lib" / "run_scan.sh"


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
    db.execute(
        text("UPDATE scan_runs SET status=:s WHERE id=:id"),
        {"s": status, "id": scan_run_id},
    )
    db.commit()


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
        )

        for raw_line in proc.stdout:
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
        while True:
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
