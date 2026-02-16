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
_MAX_ITERATIONS = 600  # 20 minutes max stream duration (600 * 2s)


async def _event_stream(scan_id: int, last_event_id: int = 0):
    """Yield SSE lines backed entirely by ScanEvent rows in the database."""
    db_conn = Database()
    db_conn.connect()
    idle = 0
    try:
        for _ in range(_MAX_ITERATIONS):
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
            if scan_run.status in ("completed", "failed", "stopped"):
                yield f"data: {json.dumps({'event': 'completed', 'status': scan_run.status, 'scan_id': scan_id})}\n\n"
                break

            # No new events — send heartbeat every ~30 s of idle
            if not new_events:
                idle += 1
                if idle % 15 == 0:
                    yield f"data: {json.dumps({'event': 'heartbeat', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"

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
        db_conn.connect()
        try:
            for _ in range(_MAX_ITERATIONS):
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

    async def _alert_gen():
        db_conn = Database()
        db_conn.connect()
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
                    .limit(20)
                    .all()
                )
                for ev in alerts:
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
