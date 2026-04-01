"""Fix phase and phases fields for completed scans that have empty phase data."""
import sqlite3, json, os

db = os.path.join(os.path.dirname(__file__), '..', 'technieum.db')
conn = sqlite3.connect(db)

# Find all completed scans with empty phases
rows = conn.execute(
    "SELECT id, domain, status, phase, phases FROM scan_runs WHERE status='completed'"
).fetchall()

for row in rows:
    scan_id, domain, status, phase, phases_raw = row
    phases = {}
    try:
        phases = json.loads(phases_raw) if phases_raw else {}
    except Exception:
        phases = {}

    if not phases:
        # Mark all 4 phases as done since scan is completed
        phases = {
            '1_discovery': True,
            '2_intel': True,
            '3_content': True,
            '4_vulnscan': True
        }
        conn.execute(
            "UPDATE scan_runs SET phase=4, phases=? WHERE id=?",
            (json.dumps(phases), scan_id)
        )
        print(f"Fixed scan {scan_id} ({domain}): phase=4, phases set to all-complete")
    else:
        print(f"Scan {scan_id} ({domain}): already has phase data, skipping")

conn.commit()
conn.close()
print("Done.")
