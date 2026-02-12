from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from api.config import get_db_path

router = APIRouter(prefix="/findings", tags=["findings"])


def get_db():
    from db.database import DatabaseManager
    return DatabaseManager(get_db_path())


@router.get("/{target}")
async def get_findings(target: str, severity: Optional[str] = None):
    """Get vulnerabilities/findings for a target."""
    db = get_db()
    try:
        q = "SELECT id, target, host, tool, severity, name, info, cve, discovered_at FROM vulnerabilities WHERE target = ?"
        params = [target]
        if severity:
            q += " AND severity = ?"
            params.append(severity)
        q += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, name"
        rows = db.fetchall(q, tuple(params))
        return {"target": target, "findings": [dict(r) for r in rows]}
    finally:
        db.close()


@router.get("/{target}/summary")
async def get_findings_summary(target: str):
    """Get finding counts by severity for a target."""
    db = get_db()
    try:
        stats = db.get_stats(target)
        if not stats:
            raise HTTPException(status_code=404, detail="Target not found")
        return {
            "target": target,
            "total": stats["vulnerabilities"],
            "critical": stats["critical_vulns"],
            "high": stats["high_vulns"],
            "medium": 0,  # could add COUNT in DB
            "low": 0,
            "info": 0,
        }
    finally:
        db.close()
