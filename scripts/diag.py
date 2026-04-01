import sqlite3

conn = sqlite3.connect("technieum.db")
c = conn.cursor()

print("=== scan_runs ===")
c.execute("SELECT id, domain, status, phase, created_at, completed_at FROM scan_runs ORDER BY id DESC")
for r in c.fetchall():
    print(r)

print("\n=== scan_jobs ===")
c.execute("SELECT id, scan_run_id, status, worker_id, started_at, finished_at, error FROM scan_jobs ORDER BY id DESC")
for r in c.fetchall():
    print(r)

print("\n=== last 20 scan_events for scan_run 2 ===")
try:
    c.execute("SELECT id, event_type, level, message, created_at FROM scan_events WHERE scan_run_id=2 ORDER BY id DESC LIMIT 20")
    for r in c.fetchall():
        print(r)
except Exception as e:
    print("scan_events error:", e)

conn.close()
