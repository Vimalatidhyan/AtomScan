"""
Reset a stuck scan back to 'queued' so the worker can re-claim it.
Usage: python3 scripts/reset_stuck_scan.py <scan_run_id>
       python3 scripts/reset_stuck_scan.py 2
"""
import sqlite3
import sys

scan_id = int(sys.argv[1]) if len(sys.argv) > 1 else 2

conn = sqlite3.connect("technieum.db")
cur = conn.cursor()

# Confirm current state
cur.execute("SELECT id, domain, status, phase FROM scan_runs WHERE id=?", (scan_id,))
run = cur.fetchone()
cur.execute("SELECT id, status, worker_id, finished_at FROM scan_jobs WHERE scan_run_id=?", (scan_id,))
job = cur.fetchone()

if not run:
    print(f"[ERROR] scan_run id={scan_id} not found")
    conn.close()
    sys.exit(1)

print(f"[BEFORE] scan_runs  : id={run[0]} domain={run[1]} status={run[2]} phase={run[3]}")
print(f"[BEFORE] scan_jobs  : {job}")

if run[2] not in ("running", "failed"):
    print(f"[SKIP] scan is already '{run[2]}', nothing to do")
    conn.close()
    sys.exit(0)

# Reset scan_runs
cur.execute(
    "UPDATE scan_runs SET status='queued', phase=0, completed_at=NULL WHERE id=?",
    (scan_id,),
)

# Reset scan_jobs (clear worker ownership so any worker can claim it)
cur.execute(
    "UPDATE scan_jobs SET status='queued', worker_id=NULL, started_at=NULL, finished_at=NULL, error=NULL WHERE scan_run_id=?",
    (scan_id,),
)

conn.commit()

# Confirm after
cur.execute("SELECT id, domain, status, phase FROM scan_runs WHERE id=?", (scan_id,))
run2 = cur.fetchone()
cur.execute("SELECT id, status, worker_id, finished_at FROM scan_jobs WHERE scan_run_id=?", (scan_id,))
job2 = cur.fetchone()

print(f"\n[AFTER]  scan_runs  : id={run2[0]} domain={run2[1]} status={run2[2]} phase={run2[3]}")
print(f"[AFTER]  scan_jobs  : {job2}")
print(f"\n[OK] Scan {scan_id} reset to 'queued'. The worker will pick it up within 5 seconds.")

conn.close()
