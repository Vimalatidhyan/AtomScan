"""Server-Sent Events streaming routes.

All events are read from the ``scan_events`` table written by the worker.
No synthetic data, no hard-coded strings — if a row isn't in the DB it
isn't sent.
"""
import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from app.db.database import Database
from app.db.models import ScanEvent, ScanProgress, ScanRun

router = APIRouter()

_POLL_INTERVAL = 2   # seconds between DB polls while waiting for new events
# No hard iteration cap — stream runs until scan completes/fails/stops.
# Two-layer keep-alive strategy:
#   1. SSE comment ping (': \n\n') every poll — zero-overhead HTTP layer keep-alive
#      that satisfies uvicorn, nginx, and browser 30-60s idle-close timers.
#   2. JSON heartbeat event every 15 polls (~30 s) — lets the frontend confirm
#      the stream is genuinely alive (not just a stale TCP connection).


async def _event_stream(scan_id: int, last_event_id: int = 0):
    """Yield SSE lines backed entirely by ScanEvent rows in the database.

    Streams indefinitely until the scan reaches a terminal state
    (completed / failed / stopped).  Heartbeats every ~30 s prevent
    proxy / browser connection timeouts during silent tool phases.
    """
    db_conn = Database()
    try:
        db_conn.connect()
    except Exception as exc:
        yield f"data: {json.dumps({'event': 'error', 'message': f'Database connection failed: {exc}'})}\n\n"
        return
    idle = 0
    try:
        while True:  # runs until terminal scan status — no hard time cap
            # Refresh session state so we see rows committed by the worker
            db_conn.session.expire_all()

            # Fetch new events since last delivered id
            new_events = (
                db_conn.session.query(ScanEvent)
                .filter(
                    ScanEvent.scan_run_id == scan_id,
                    ScanEvent.id > last_event_id,
                )
                .order_by(ScanEvent.id)
                .limit(50)
                .all()
            )

            for ev in new_events:
                payload = {
                    "id": ev.id,
                    "event": ev.event_type,
                    "level": ev.level,
                    "message": ev.message,
                    "phase": ev.phase,
                    "timestamp": ev.created_at.isoformat()
                    if ev.created_at
                    else datetime.now(timezone.utc).isoformat(),
                }
                if ev.data:
                    try:
                        payload["data"] = json.loads(ev.data)
                    except (json.JSONDecodeError, TypeError):
                        payload["data"] = ev.data
                yield f"data: {json.dumps(payload)}\n\n"
                last_event_id = ev.id
                idle = 0

            # Check terminal scan state
            scan_run = (
                db_conn.session.query(ScanRun)
                .filter(ScanRun.id == scan_id)
                .first()
            )
            if scan_run is None:
                yield f"data: {json.dumps({'event': 'error', 'message': 'Scan not found'})}\n\n"
                break
            if scan_run.status in ("completed", "failed", "stopped", "paused"):
                # Only terminate AFTER all remaining events have been drained.
                # Structured data events (alive_hosts, asn_data, etc.) are
                # emitted during ingestion at the end of the scan — breaking
                # early would skip them when there are more than 50 events.
                if not new_events:
                    if scan_run.status != "paused":
                        yield f"data: {json.dumps({'event': 'completed', 'status': scan_run.status, 'scan_id': scan_id})}\n\n"
                    break

            # SSE comment ping every poll — keeps the HTTP connection alive through
            # uvicorn/nginx/browser idle-close timers (cost: ~3 bytes per 2 s).
            yield ": \n\n"

            # JSON heartbeat event every ~30 s so the frontend can distinguish
            # a live-but-quiet stream from a dropped connection.
            if not new_events:
                idle += 1
                if idle % 15 == 0:
                    yield f"data: {json.dumps({'event': 'heartbeat', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            else:
                idle = 0

            await asyncio.sleep(_POLL_INTERVAL)

    except Exception as exc:
        yield f"data: {json.dumps({'event': 'error', 'message': str(exc)})}\n\n"
    finally:
        db_conn.close()


@router.get("/logs/{scan_id}", summary="Stream scan logs (SSE)")
async def stream_logs(
    scan_id: int,
    last_event_id: int = Query(0, alias="lastEventId", ge=0),
):
    """Stream scan log events via SSE.

    The client may pass ``?lastEventId=N`` to resume from a known position
    without re-receiving already-seen events.
    """
    return StreamingResponse(
        _event_stream(scan_id, last_event_id=last_event_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/scan/{scan_id}", summary="Stream scan updates (SSE)")
async def stream_scan(
    scan_id: int,
    last_event_id: int = Query(0, alias="lastEventId", ge=0),
):
    """Stream all scan events (logs, progress, stats) via SSE."""
    return StreamingResponse(
        _event_stream(scan_id, last_event_id=last_event_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/progress/{scan_id}", summary="Stream progress (SSE)")
async def stream_progress(
    scan_id: int,
    last_event_id: int = Query(0, alias="lastEventId", ge=0),
):
    """Stream progress-type events for a scan via SSE."""

    async def _progress_only(scan_id: int, last_event_id: int):
        db_conn = Database()
        try:
            db_conn.connect()
        except Exception as exc:
            yield f"data: {json.dumps({'event': 'error', 'message': f'Database connection failed: {exc}'})}\n\n"
            return
        try:
            while True:  # runs until terminal scan status
                db_conn.session.expire_all()

                new_events = (
                    db_conn.session.query(ScanEvent)
                    .filter(
                        ScanEvent.scan_run_id == scan_id,
                        ScanEvent.id > last_event_id,
                        ScanEvent.event_type.in_(["progress", "completed", "error", "stats"]),
                    )
                    .order_by(ScanEvent.id)
                    .limit(20)
                    .all()
                )

                for ev in new_events:
                    payload = {
                        "id": ev.id,
                        "event": ev.event_type,
                        "message": ev.message,
                        "phase": ev.phase,
                        "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                    }
                    if ev.data:
                        try:
                            payload["data"] = json.loads(ev.data)
                        except (json.JSONDecodeError, TypeError):
                            pass
                    yield f"data: {json.dumps(payload)}\n\n"
                    last_event_id = ev.id

                # Also send a snapshot from ScanProgress every poll
                prog = (
                    db_conn.session.query(ScanProgress)
                    .filter(ScanProgress.scan_run_id == scan_id)
                    .first()
                )
                if prog:
                    snap = {
                        "event": "progress_snapshot",
                        "phase": prog.current_phase,
                        "percentage": prog.progress_percentage,
                        "status": prog.status,
                        "subdomains_found": prog.subdomains_found,
                        "vulnerabilities_found": prog.vulnerabilities_found,
                    }
                    yield f"data: {json.dumps(snap)}\n\n"

                scan_run = (
                    db_conn.session.query(ScanRun)
                    .filter(ScanRun.id == scan_id)
                    .first()
                )
                if scan_run and scan_run.status in ("completed", "failed", "stopped"):
                    yield f"data: {json.dumps({'event': 'completed', 'status': scan_run.status})}\n\n"
                    break

                await asyncio.sleep(_POLL_INTERVAL)

        except Exception as exc:
            yield f"data: {json.dumps({'event': 'error', 'message': str(exc)})}\n\n"
        finally:
            db_conn.close()

    return StreamingResponse(
        _progress_only(scan_id, last_event_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/alerts", summary="Stream security alerts (SSE)")
async def stream_alerts():
    """Stream error/critical events across all active scans."""

    # Tool-availability noise — these never belong in the alert bell (warning OR error level).
    _NOISE_KEYWORDS = (
        "not found", "not set", "not installed", "not a git repo",
        "install:", "skipping", "falling back", "relying on",
        "no output", "no scan targets", "no scan hosts",
        "no subdomains", "no javascript", "no wordlist",
        "creating basic", "failed or timed out",
        "api credentials not set", "api_key not set",
        # amass / libpostal
        "requires libpostal", "requires sudo", "amass is installed but",
        "amass not found", "subcommand not available", "passive enum",
        "no results (exit non-zero",
        # tool-specific missing
        "cariddi not found", "hakrawler not found",
        "gitleaks not found", "no urls to scan yet",
        "dnsbruter not found", "dnsprober not found",
        "getsubsidiaries not found", "sublist3r not found",
        # cloud/asn noisy fallback warnings
        "s3scanner failed for all known flag styles",
        "s3scanner yielded no results or encountered an error",
        "asnmap returned no valid cidrs",
        "pdcp auth issue",
        # WSL-mounted path performance advisory (non-security)
        "running under /mnt/",
        "running under /mnt/*",
        "windows filesystem",
    )

    async def _alert_gen():
        from datetime import timedelta
        db_conn = Database()
        # Deduplicate repeated warnings from the same scan/message pair during a stream session.
        seen_alert_fingerprints: set[tuple[int, str, str]] = set()
        try:
            db_conn.connect()
        except Exception as exc:
            yield f"data: {json.dumps({'event': 'error', 'message': f'Database connection failed: {exc}'})}\n\n"
            return
        # Only stream events from the last 60 minutes — never replay old historical
        # warnings from completed scans.  Prevents notification-bell flooding on
        # page load from events stored days/weeks ago.
        try:
            cutoff_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
            baseline = db_conn.session.query(ScanEvent.id).filter(
                ScanEvent.created_at < cutoff_time
            ).order_by(ScanEvent.id.desc()).limit(1).scalar()
            last_id = baseline if baseline is not None else 0
        except Exception:
            last_id = 0
        try:
            for _ in range(300):  # 10 minutes
                db_conn.session.expire_all()
                alerts = (
                    db_conn.session.query(ScanEvent)
                    .filter(
                        ScanEvent.id > last_id,
                        ScanEvent.level.in_(["error", "warning"]),
                    )
                    .order_by(ScanEvent.id)
                    .limit(50)
                    .all()
                )
                for ev in alerts:
                    # Drop raw JSON blobs (ffuf/nuclei output stored before fix)
                    if ev.message and ev.message.lstrip().startswith(("{", "[")):
                        last_id = ev.id
                        continue
                    # Skip tool-availability noise for BOTH warning and error levels
                    if ev.message and any(
                        kw in ev.message.lower() for kw in _NOISE_KEYWORDS
                    ):
                        last_id = ev.id
                        continue
                    msg = (ev.message or "").strip()
                    fingerprint = (
                        int(ev.scan_run_id or 0),
                        (ev.level or "").lower(),
                        msg.lower(),
                    )
                    if fingerprint in seen_alert_fingerprints:
                        last_id = ev.id
                        continue
                    seen_alert_fingerprints.add(fingerprint)
                    payload = {
                        "event": "alert",
                        "level": ev.level,
                        "scan_run_id": ev.scan_run_id,
                        "message": ev.message,
                        "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                    last_id = ev.id
                if not alerts:
                    yield f"data: {json.dumps({'event': 'heartbeat', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
                await asyncio.sleep(_POLL_INTERVAL)
        except Exception as exc:
            yield f"data: {json.dumps({'event': 'error', 'message': str(exc)})}\n\n"
        finally:
            db_conn.close()

    return StreamingResponse(
        _alert_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
