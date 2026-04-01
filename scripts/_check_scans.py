"""Check recent scan statuses and scan events for the latest scan."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.db.database import SessionLocal
from sqlalchemy import text

db = SessionLocal()
try:
    rows = db.execute(text('SELECT id, domain, status, phase, created_at FROM scan_runs ORDER BY id DESC LIMIT 5')).fetchall()
    print("=== Recent Scans ===")
    for r in rows:
        print(dict(r._mapping))

    if rows:
        latest_id = rows[0][0]
        print(f"\n=== Latest Scan Events (scan_run_id={latest_id}) ===")
        events = db.execute(text(
            'SELECT level, message, created_at FROM scan_events WHERE scan_run_id=:sid ORDER BY id DESC LIMIT 20'
        ), {'sid': latest_id}).fetchall()
        for e in events:
            print(f"[{e[0]}] {e[2]} — {e[1]}")

    print("\n=== Scan Jobs ===")
    jobs = db.execute(text('SELECT id, scan_run_id, status, error FROM scan_jobs ORDER BY id DESC LIMIT 5')).fetchall()
    for j in jobs:
        print(dict(j._mapping))
finally:
    db.close()
