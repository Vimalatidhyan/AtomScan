from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from api.config import get_db_path

router = APIRouter(prefix="/assets", tags=["assets"])


def get_db():
    from db.database import DatabaseManager
    return DatabaseManager(get_db_path())


@router.get("/targets")
async def list_targets():
    """List all targets in the database."""
    db = get_db()
    try:
        rows = db.fetchall("SELECT DISTINCT target FROM scan_progress ORDER BY target")
        return {"targets": [r["target"] for r in rows]}
    finally:
        db.close()


@router.get("/stats/{target}")
async def get_asset_stats(target: str):
    """Get asset statistics and phase progress for a target (Phases 1–4: Discovery, Intel, Content, Vuln)."""
    db = get_db()
    try:
        stats = db.get_stats(target)
        if not stats:
            raise HTTPException(status_code=404, detail="Target not found")
        progress = db.get_progress(target)
        if progress:
            stats["phases"] = {
                "1_discovery": bool(progress.get("phase1_done")),
                "2_intel": bool(progress.get("phase2_done")),
                "3_content": bool(progress.get("phase3_done")),
                "4_vuln": bool(progress.get("phase4_done")),
            }
            stats["phase_list"] = [
                {"id": 1, "name": "Discovery", "done": bool(progress.get("phase1_done"))},
                {"id": 2, "name": "Intel", "done": bool(progress.get("phase2_done"))},
                {"id": 3, "name": "Content", "done": bool(progress.get("phase3_done"))},
                {"id": 4, "name": "Vuln", "done": bool(progress.get("phase4_done"))},
            ]
        else:
            stats["phases"] = None
            stats["phase_list"] = []
        return stats
    finally:
        db.close()


@router.get("/progress/{target}")
async def get_target_progress(target: str):
    """Get phase completion progress for a target (Phases 1–4: Discovery, Intel, Content, Vuln)."""
    db = get_db()
    try:
        progress = db.get_progress(target)
        if not progress:
            raise HTTPException(status_code=404, detail="Target not found")
        return {
            "target": target,
            "phase1_done": bool(progress.get("phase1_done")),
            "phase2_done": bool(progress.get("phase2_done")),
            "phase3_done": bool(progress.get("phase3_done")),
            "phase4_done": bool(progress.get("phase4_done")),
            "phases": [
                {"id": 1, "name": "Discovery", "done": bool(progress.get("phase1_done"))},
                {"id": 2, "name": "Intel", "done": bool(progress.get("phase2_done"))},
                {"id": 3, "name": "Content", "done": bool(progress.get("phase3_done"))},
                {"id": 4, "name": "Vuln", "done": bool(progress.get("phase4_done"))},
            ],
            "started_at": progress.get("started_at"),
            "updated_at": progress.get("updated_at"),
        }
    finally:
        db.close()


@router.get("/subdomains/{target}")
async def get_subdomains(target: str, alive_only: bool = False):
    """Get subdomains for a target."""
    db = get_db()
    try:
        q = "SELECT host, ip, is_alive, status_code, source_tools FROM subdomains WHERE target = ?"
        params = [target]
        if alive_only:
            q += " AND is_alive = 1"
        q += " ORDER BY is_alive DESC, host"
        rows = db.fetchall(q, tuple(params))
        return {"target": target, "subdomains": [dict(r) for r in rows]}
    finally:
        db.close()


@router.get("/ports/{target}")
async def get_ports(target: str):
    """Get open ports for a target."""
    db = get_db()
    try:
        rows = db.fetchall(
            "SELECT host, port, protocol, service, version FROM ports WHERE target = ? ORDER BY host, port",
            (target,),
        )
        return {"target": target, "ports": [dict(r) for r in rows]}
    finally:
        db.close()
