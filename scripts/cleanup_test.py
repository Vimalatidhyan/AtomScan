"""Remove any non-trutrip.co test scan runs."""
import sqlite3, os
db_path = os.path.join(os.path.dirname(__file__), '..', 'technieum.db')
conn = sqlite3.connect(db_path)
cur = conn.cursor()
cur.execute("DELETE FROM scan_runs WHERE domain != 'trutrip.co'")
conn.commit()
print(f"Removed {cur.rowcount} test scan(s)")
conn.close()
