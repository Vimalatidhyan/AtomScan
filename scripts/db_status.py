#!/usr/bin/env python3
"""Quick DB status check: show row counts and recent scan data."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "technieum.db")
conn = sqlite3.connect(DB)
c = conn.cursor()

c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [r[0] for r in c.fetchall()]
print("=== Tables and Row Counts ===")
for t in tables:
    c.execute(f"SELECT COUNT(*) FROM {t}")
    print(f"  {t}: {c.fetchone()[0]}")

print("\n=== Scan Runs ===")
c.execute("SELECT id, domain, status, created_at FROM scan_runs ORDER BY id DESC LIMIT 5")
for row in c.fetchall():
    print(f"  id={row[0]} domain={row[1]} status={row[2]} created={row[3]}")

print("\n=== Recent Subdomains ===")
c.execute("SELECT id, scan_run_id, subdomain, is_alive FROM subdomains LIMIT 10")
for row in c.fetchall():
    print(f"  scan_run_id={row[1]} subdomain={row[2]} alive={row[3]}")

conn.close()
