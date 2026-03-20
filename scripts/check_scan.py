import sqlite3
conn = sqlite3.connect("technieum.db")
cur = conn.cursor()

# scan_runs
cur.execute("PRAGMA table_info(scan_runs)")
cols = [c[1] for c in cur.fetchall()]
print("=== scan_runs ===", cols)
cur.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 5")
for r in cur.fetchall():
    print(dict(zip(cols, r)))

# scan_jobs
try:
    cur.execute("PRAGMA table_info(scan_jobs)")
    jcols = [c[1] for c in cur.fetchall()]
    print("\n=== scan_jobs ===", jcols)
    cur.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT 5")
    for r in cur.fetchall():
        print(dict(zip(jcols, r)))
except Exception as e:
    print("scan_jobs error:", e)

conn.close()
