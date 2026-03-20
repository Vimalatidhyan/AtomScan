#!/usr/bin/env python3
"""
Re-ingest scan results from disk output into the database.
Also resets stuck 'running' scans and triggers ingestion for scan_run_id=1.

Usage:  python3 scripts/reingest.py [scan_run_id]
"""
import sys
import os

# Add repo root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from pathlib import Path

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./technieum.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)

scan_run_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1

db = Session()

try:
    # Get scan info
    row = db.execute(
        text("SELECT id, domain, status FROM scan_runs WHERE id=:id"),
        {"id": scan_run_id}
    ).fetchone()

    if not row:
        print(f"ERROR: scan_run_id={scan_run_id} not found")
        sys.exit(1)

    sid, domain, status = row
    print(f"Scan: id={sid} domain={domain} status={status}")

    # Find output directory
    repo_root = Path(__file__).resolve().parents[1]
    output_base = Path(os.environ.get("TECHNIEUM_OUTPUT_DIR", str(repo_root / "output")))
    output_dir = output_base / f"{domain.replace('.', '_')}_{scan_run_id}"

    print(f"Output dir: {output_dir}")
    if not output_dir.exists():
        print(f"ERROR: Output directory not found: {output_dir}")
        sys.exit(1)

    # List key output files
    for f in ["subdomains.txt", "nmap.xml", "nmap.txt", "nuclei.json"]:
        fp = output_dir / f
        if fp.exists():
            print(f"  Found: {f} ({fp.stat().st_size} bytes)")
        else:
            print(f"  Missing: {f}")

    # Import and run ingestion
    print("\nRunning ingestion...")
    from app.workers.worker import _ingest_results, _emit_event, _update_progress

    _emit_event(db, scan_run_id, "log", "info",
                "[reingest] Manual re-ingestion triggered")

    _ingest_results(scan_run_id, domain, output_dir, db)

    # Mark scan completed
    db.execute(
        text("UPDATE scan_runs SET status='completed', completed_at=datetime('now') WHERE id=:id"),
        {"id": scan_run_id}
    )
    db.execute(
        text("UPDATE scan_jobs SET status='done', finished_at=datetime('now') WHERE scan_run_id=:id"),
        {"id": scan_run_id}
    )
    _update_progress(db, scan_run_id, status="done", progress_percentage=100)
    db.commit()

    print("\n=== Ingestion complete ===")

    # Verify DB counts
    import sqlite3
    conn2 = sqlite3.connect(str(repo_root / "technieum.db"))
    c = conn2.cursor()
    for t in ["subdomains", "port_scans", "vulnerabilities"]:
        c.execute(f"SELECT COUNT(*) FROM {t}")
        print(f"  {t}: {c.fetchone()[0]} rows")
    conn2.close()

finally:
    db.close()

print("\nDone. Refresh the Attack Graph page to see data.")
