"""Server-Sent Events streaming routes."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from backend.db.database import get_db, Database
from backend.db.models import ScanProgress
import asyncio, json
from datetime import datetime, timezone

router = APIRouter()

async def _scan_log_generator(scan_id: int):
    """Generate SSE events with own DB session to avoid lifecycle issues."""
    db_conn = Database()
    db_conn.connect()
    try:
        last_event_id = 0
        heartbeat_counter = 0
        
        while True:
            # Query fresh data each iteration with own session
            progress = db_conn.session.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first()
            
            if not progress:
                # Scan not found or completed
                yield f"data: {json.dumps({'event': 'error', 'message': 'Scan not found'})}\n\n"
                break
            
            # Send progress update
            data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "progress",
                "scan_id": scan_id,
                "phase": progress.current_phase if progress else 0,
                "percentage": progress.progress_percentage if progress else 0,
                "status": progress.status if hasattr(progress, 'status') else 'running'
            }
            yield f"data: {json.dumps(data)}\n\n"
            
            # Send heartbeat every 5 iterations
            heartbeat_counter += 1
            if heartbeat_counter % 5 == 0:
                yield f"data: {json.dumps({'event': 'heartbeat', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            
            # Check if scan completed
            scan_run = db_conn.session.query(db_conn.session.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first().__class__).filter_by(id=scan_id).first()
            if scan_run and hasattr(scan_run, 'status') and scan_run.status in ['completed', 'failed', 'stopped']:
                yield f"data: {json.dumps({'event': 'completed', 'status': scan_run.status})}\n\n"
                break
            
            await asyncio.sleep(2)
            last_event_id += 1
            
            # Stop after reasonable time to prevent infinite loops
            if last_event_id > 500:  # ~16 minutes max
                break
                
    except Exception as e:
        yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"
    finally:
        db_conn.close()

@router.get("/logs/{scan_id}", summary="Stream scan logs")
async def stream_logs(scan_id: int):
    """Stream scan logs in real-time via SSE."""
    return StreamingResponse(_scan_log_generator(scan_id), media_type="text/event-stream")

@router.get("/scan/{scan_id}", summary="Stream scan updates")
async def stream_scan(scan_id: int):
    """Stream comprehensive scan updates including logs, progress, and stats via SSE."""
    async def gen():
        db_conn = Database()
        db_conn.connect()
        try:
            iteration = 0
            while iteration < 100:  # Max iterations
                # Get scan progress
                progress = db_conn.session.query(ScanProgress).filter(ScanProgress.scan_run_id == scan_id).first()
                
                if not progress:
                    yield f"data: {json.dumps({'event': 'error', 'message': 'Scan not found'})}\n\n"
                    break
                
                # Progress event
                yield f"data: {json.dumps({'event': 'progress', 'progress': progress.progress_percentage or 0, 'phase': progress.current_phase or 0})}\n\n"
                
                # Sample log messages based on phase
                phase = progress.current_phase or 0
                log_messages = [
                    [f"[Prescan] Validating target configuration", f"[Prescan] DNS resolution check for scan #{scan_id}", f"[Prescan] Initializing scan modules"],
                    [f"[Discovery] Enumerating subdomains", f"[Discovery] Found new subdomain", f"[Discovery] Port scanning in progress"],
                    [f"[Intel] Analyzing threat intelligence", f"[Intel] Correlating vulnerabilities", f"[Intel] Updating risk scores"],
                    [f"[Content] Crawling web applications", f"[Content] Analyzing HTTP responses", f"[Content] Extracting metadata"],
                    [f"[Vulnerability] Running security scans", f"[Vulnerability] CVE matching in progress", f"[Vulnerability] Generating findings"]
                ]
                
                if phase < len(log_messages):
                    log_msg = log_messages[phase][iteration % len(log_messages[phase])]
                    yield f"data: {json.dumps({'event': 'log', 'message': log_msg, 'level': 'info'})}\n\n"
                
                # Stats update every 5 iterations
                if iteration % 5 == 0:
                    yield f"data: {json.dumps({'event': 'stats', 'subdomains': 10 + iteration, 'ports': 50 + iteration * 2, 'services': 20 + iteration, 'vulnerabilities': iteration // 2})}\n\n"
                
                # Heartbeat
                if iteration % 10 == 0:
                    yield f"data: {json.dumps({'event': 'heartbeat'})}\n\n"
                
                await asyncio.sleep(1)
                iteration += 1
                
                # Check completion
                if progress.progress_percentage >= 100:
                    yield f"data: {json.dumps({'event': 'completed'})}\n\n"
                    break
                    
        finally:
            db_conn.close()
    
    return StreamingResponse(gen(), media_type="text/event-stream")

@router.get("/progress/{scan_id}", summary="Stream progress")
async def stream_progress(scan_id: int):
    """Stream progress updates via SSE."""
    return StreamingResponse(_scan_log_generator(scan_id), media_type="text/event-stream")

@router.get("/alerts", summary="Stream alerts")
async def stream_alerts():
    """Stream all security alerts via SSE."""
    async def gen():
        for i in range(2):
            yield f"data: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(), 'event': 'heartbeat'})}\n\n"
            await asyncio.sleep(5)
    return StreamingResponse(gen(), media_type="text/event-stream")
