import sqlite3

conn = sqlite3.connect("technieum.db")
c = conn.cursor()

tables = ["scan_events", "scan_jobs", "scan_runs"]
for t in tables:
    try:
        c.execute(f"DELETE FROM {t}")
        print(f"[OK] cleared {t} ({c.rowcount} rows deleted)")
    except Exception as e:
        print(f"[SKIP] {t}: {e}")

conn.commit()
conn.close()
print("\nDB cleanup done.")
