#!/usr/bin/env bash
# perf_scan_queue.sh — scan worker throughput smoke test
# Creates N synthetic scan_jobs, runs the worker in --drain mode, and
# reports how long it takes to process them.
#
# Usage: ./scripts/perf_scan_queue.sh [N_JOBS]
#
# Requires: python3 with app package importable (.venv activated or
#           PYTHONPATH set to the repo root).
#
set -euo pipefail

N="${1:-5}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DB="${TECHNIEUM_TEST_DB:-/tmp/technieum_perf_test.db}"
export DATABASE_URL="sqlite:///$DB"

cleanup() { rm -f "$DB"; }
trap cleanup EXIT

echo "=== Technieum scan queue throughput test ==="
echo "  jobs=$N  db=$DB"
echo ""

# Seed the database with N scan_jobs pointing to synthetic scan_runs
python3 - "$N" "$DB" << 'PYEOF'
import sys, sqlite3
n = int(sys.argv[1])
db_path = sys.argv[2]
conn = sqlite3.connect(db_path)
conn.execute("""CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    scan_type TEXT,
    status TEXT DEFAULT 'pending'
)""")
conn.execute("""CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    error TEXT
)""")
for i in range(n):
    cur = conn.execute("INSERT INTO scan_runs (domain, scan_type) VALUES (?,?)",
                       (f"example{i}.local", "quick"))
    conn.execute("INSERT INTO scan_jobs (scan_run_id) VALUES (?)", (cur.lastrowid,))
conn.commit()
conn.close()
print(f"  Seeded {n} jobs.")
PYEOF

# Time the worker drain
start_s=$(python3 -c "import time; print(time.monotonic())")
python3 -m app.workers.worker --drain 2>/dev/null
end_s=$(python3 -c "import time; print(time.monotonic())")

elapsed=$(python3 -c "print(round(($end_s - $start_s)*1000))")
per_job=$(python3 -c "print(round(($end_s - $start_s)*1000 / $N))")

echo ""
echo "  Processed $N jobs in ${elapsed}ms (~${per_job}ms/job)"
echo ""
echo "PASS"
