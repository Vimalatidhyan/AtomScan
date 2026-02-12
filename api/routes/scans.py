import asyncio
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from api.config import get_db_path, ROOT

router = APIRouter(prefix="/scans", tags=["scans"])

# In-memory scan state (in production use Redis or DB)
_active_scans: Dict[str, dict] = {}


def _normalize_target(raw: str) -> str:
    """Convert URL or domain with trailing slash to bare domain (e.g. pcis.education)."""
    s = (raw or "").strip()
    if not s:
        return ""
    if "://" in s:
        from urllib.parse import urlparse
        parsed = urlparse(s)
        host = parsed.netloc or parsed.path
    else:
        host = s
    host = host.rstrip("/").split("/")[0].split(":")[0]
    return host.lower() if host else s


def get_reconx():
    from db.database import DatabaseManager
    from reconx import ReconX
    return ReconX, DatabaseManager


def run_scan_sync(scan_id: str, target: str, phases: List[int], output_dir: str, db_path: str, test_mode: bool = False):
    """Run ReconX scan in a thread (blocking). test_mode=True uses mock data and completes in seconds."""
    reconx = None
    try:
        ReconX, _ = get_reconx()
        reconx = ReconX(
            targets=[target],
            output_dir=output_dir,
            db_path=db_path,
            test_mode=test_mode,
        )
        _active_scans[scan_id]["current_phase"] = 1
        _active_scans[scan_id]["progress"] = 10
        reconx.run(phases=phases)
        _active_scans[scan_id]["status"] = "completed"
        _active_scans[scan_id]["progress"] = 100
        _active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat() + "Z"
    except Exception as e:
        _active_scans[scan_id]["status"] = "failed"
        _active_scans[scan_id]["error"] = str(e)
        _active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat() + "Z"
    finally:
        if reconx is not None and hasattr(reconx, "db"):
            reconx.db.close()


@router.post("")
async def create_scan(
    target: str,
    phases: Optional[str] = "1,2,3,4",
    test_mode: Optional[bool] = False,
    background_tasks: BackgroundTasks = None,
):
    """Start a new scan. Use test_mode=true for a quick mock scan (no real tools required)."""
    # Normalize to bare domain (strip https://, trailing slash, path)
    target = _normalize_target(target.strip())
    if not target:
        raise HTTPException(status_code=400, detail="Invalid target (use a domain e.g. example.com)")
    phase_list = [int(p.strip()) for p in phases.split(",") if p.strip()]
    if not phase_list or not all(1 <= p <= 4 for p in phase_list):
        raise HTTPException(status_code=400, detail="Phases must be 1,2,3,4")
    # Register target in DB immediately so it appears in the UI
    from db.database import DatabaseManager
    db = DatabaseManager(get_db_path())
    db.init_target(target)
    db.close()

    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    output_dir = str(ROOT / "output" / "api" / scan_id)
    db_path = get_db_path()

    _active_scans[scan_id] = {
        "scan_id": scan_id,
        "target": target,
        "status": "running",
        "progress": 0,
        "current_phase": None,
        "started_at": datetime.utcnow().isoformat() + "Z",
        "completed_at": None,
        "error": None,
    }

    import concurrent.futures
    _executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def run():
        run_scan_sync(scan_id, target, phase_list, output_dir, db_path, test_mode=test_mode)

    loop = asyncio.get_event_loop()
    loop.run_in_executor(_executor, run)

    return {
        "scan_id": scan_id,
        "target": target,
        "status": "started",
        "phases": phase_list,
        "test_mode": test_mode,
    }


@router.get("")
async def list_scans():
    """List all scans (active + targets from DB)."""
    from db.database import DatabaseManager
    db = DatabaseManager(get_db_path())
    rows = db.fetchall("SELECT target, updated_at FROM scan_progress ORDER BY updated_at DESC")

    targets_seen = set()
    items = []
    for sid, data in _active_scans.items():
        target = data["target"]
        prog = db.get_progress(target) if target else None
        items.append({
            "scan_id": data["scan_id"],
            "target": target,
            "status": data["status"],
            "progress": data["progress"],
            "started_at": data.get("started_at"),
            "error": data.get("error"),
            "phases": {
                "1_discovery": bool(prog and prog.get("phase1_done")),
                "2_intel": bool(prog and prog.get("phase2_done")),
                "3_content": bool(prog and prog.get("phase3_done")),
                "4_vuln": bool(prog and prog.get("phase4_done")),
            } if prog else None,
        })
        targets_seen.add(target)

    for row in rows:
        t = row["target"]
        if t not in targets_seen:
            prog = db.get_progress(t)
            items.append({
                "scan_id": f"target_{t}",
                "target": t,
                "status": "completed",
                "progress": 100,
                "started_at": row["updated_at"],
                "phases": {
                    "1_discovery": bool(prog and prog.get("phase1_done")),
                    "2_intel": bool(prog and prog.get("phase2_done")),
                    "3_content": bool(prog and prog.get("phase3_done")),
                    "4_vuln": bool(prog and prog.get("phase4_done")),
                } if prog else None,
            })
    db.close()
    return {"scans": items}


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status. Includes phase completion (1=Discovery, 2=Intel, 3=Content, 4=Vuln) when available."""
    if scan_id in _active_scans:
        data = dict(_active_scans[scan_id])
        target = data.get("target")
        if target:
            from db.database import DatabaseManager
            db = DatabaseManager(get_db_path())
            prog = db.get_progress(target)
            db.close()
            if prog:
                data["phases"] = {
                    "1_discovery": bool(prog.get("phase1_done")),
                    "2_intel": bool(prog.get("phase2_done")),
                    "3_content": bool(prog.get("phase3_done")),
                    "4_vuln": bool(prog.get("phase4_done")),
                }
        return data
    # Try target-based lookup
    if scan_id.startswith("target_"):
        target = scan_id.replace("target_", "", 1)
        from db.database import DatabaseManager
        db = DatabaseManager(get_db_path())
        progress = db.get_progress(target)
        db.close()
        if progress:
            return {
                "scan_id": scan_id,
                "target": target,
                "status": "completed",
                "progress": 100,
                "current_phase": None,
                "started_at": progress.get("started_at"),
                "completed_at": progress.get("updated_at"),
                "error": None,
                "phases": {
                    "1_discovery": bool(progress.get("phase1_done")),
                    "2_intel": bool(progress.get("phase2_done")),
                    "3_content": bool(progress.get("phase3_done")),
                    "4_vuln": bool(progress.get("phase4_done")),
                },
            }
    raise HTTPException(status_code=404, detail="Scan not found")
