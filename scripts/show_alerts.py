"""Show remaining error/warning scan events in technieum.db."""
import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), '..', 'technieum.db')
DB = os.path.abspath(DB)

conn = sqlite3.connect(DB)
rows = conn.execute(
    "SELECT id, level, LEFT(message, 120) FROM scan_events WHERE level IN ('error','warning') ORDER BY id DESC LIMIT 30"
).fetchall()
if not rows:
    # SQLite doesn't have LEFT(), try SUBSTR
    rows = conn.execute(
        "SELECT id, level, substr(message,1,120) FROM scan_events WHERE level IN ('error','warning') ORDER BY id DESC LIMIT 30"
    ).fetchall()
print(f"Remaining error/warning events ({len(rows)} shown):")
for r in rows:
    print(f"  [{r[1]}] {r[2]}")
conn.close()
