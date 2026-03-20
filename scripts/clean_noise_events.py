"""Clean old tool-noise scan events from technieum.db so the notification bell starts fresh."""
import sqlite3, sys, os

DB = os.path.join(os.path.dirname(__file__), '..', 'technieum.db')
DB = os.path.abspath(DB)

NOISE_KEYWORDS = [
    "not found", "not set", "not installed", "not a git repo",
    "install:", "skipping", "falling back", "relying on",
    "no output", "no scan targets", "no scan hosts",
    "no subdomains", "no javascript", "no wordlist",
    "creating basic", "failed or timed out",
    "api credentials not set", "api_key not set",
    "requires libpostal", "requires sudo", "amass is installed but",
    "amass not found", "subcommand not available", "passive enum",
    "no results (exit non-zero",
    "cariddi not found", "hakrawler not found",
    "gitleaks not found", "no urls to scan yet",
    "dnsbruter not found", "dnsprober not found",
    "getsubsidiaries not found", "sublist3r not found",
    "amass intel not supported", "amass enum skipped",
    "amass is installed but requires libpostal",
    "potential subdomain takeovers",   # old false-count subjack entries
    "cariddi scan failed",
    "hakrawler failed",
    "gitleaks scan failed",
    "amass failed with exit code",
    "intel not supported",
]

if not os.path.exists(DB):
    print(f"DB not found: {DB}")
    sys.exit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

# Check table exists
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("Tables:", tables)

if 'scan_events' not in tables:
    print("No scan_events table found.")
    conn.close()
    sys.exit(0)

# Count before
total_before = cur.execute("SELECT COUNT(*) FROM scan_events WHERE level IN ('error','warning')").fetchone()[0]
print(f"Total error/warning events before: {total_before}")

# Delete noise events
deleted = 0
for kw in NOISE_KEYWORDS:
    r = cur.execute(
        "DELETE FROM scan_events WHERE level IN ('error','warning') AND LOWER(message) LIKE ?",
        (f"%{kw.lower()}%",)
    )
    n = r.rowcount
    if n > 0:
        print(f"  Deleted {n} events matching '{kw}'")
        deleted += n

conn.commit()

total_after = cur.execute("SELECT COUNT(*) FROM scan_events WHERE level IN ('error','warning')").fetchone()[0]
print(f"\nDeleted {deleted} noisy events total.")
print(f"Remaining error/warning events: {total_after}")

# Show remaining to confirm they're real alerts
if total_after > 0:
    print("\nRemaining events (last 10):")
    rows = cur.execute(
        "SELECT id, level, message FROM scan_events WHERE level IN ('error','warning') ORDER BY id DESC LIMIT 10"
    ).fetchall()
    for r in rows:
        print(f"  [{r[1]}] {r[2][:100]}")

conn.close()
print("\nDone.")
