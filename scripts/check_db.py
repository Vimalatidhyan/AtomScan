import sqlite3

DB = '/mnt/c/Users/Vimalatithyan/OneDrive/Desktop/Technieum-X/technieum.db'
c = sqlite3.connect(DB)
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print('Tables:', tables)

for t in tables:
    count = c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    print(f"  {t}: {count} rows")

# Check for scan_events or alerts table
for t in tables:
    if 'event' in t.lower() or 'alert' in t.lower() or 'log' in t.lower() or 'scan' in t.lower():
        print(f"\n--- {t} schema ---")
        for col in c.execute(f"PRAGMA table_info({t})").fetchall():
            print(f"  {col}")
        print(f"--- last 5 rows of {t} ---")
        try:
            rows = c.execute(f"SELECT * FROM {t} ORDER BY rowid DESC LIMIT 5").fetchall()
            for r in rows:
                print(r)
        except Exception as e:
            print(f"Error: {e}")
