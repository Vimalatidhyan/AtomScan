"""One-shot DB noise cleanup — run once then delete this file."""
import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), '..', 'technieum.db')
DB = os.path.abspath(DB)

NOISE = [
    'not found', 'not set', 'not installed', 'not a git repo',
    'install:', 'skipping', 'falling back', 'relying on',
    'no output', 'no scan targets', 'no scan hosts',
    'no subdomains', 'no javascript', 'no wordlist',
    'creating basic', 'failed or timed out',
    'api credentials not set', 'api_key not set',
    'requires libpostal', 'requires sudo',
    'amass is installed but', 'amass not found',
    'subcommand not available', 'passive enum',
    'no results (exit non-zero',
    'cariddi not found', 'hakrawler not found',
    'gitleaks not found', 'no urls to scan yet',
    'dnsbruter not found', 'dnsprober not found',
    'getsubsidiaries not found', 'sublist3r not found',
    'amass intel not supported', 'amass enum skipped',
    'potential subdomain takeovers',
    'cariddi scan failed', 'hakrawler failed',
    'gitleaks scan failed', 'amass failed with exit code',
    'intel not supported',
]

conn = sqlite3.connect(DB)
total_before = conn.execute(
    "SELECT COUNT(*) FROM scan_events WHERE level IN ('error','warning')"
).fetchone()[0]

total_deleted = 0
for kw in NOISE:
    n = conn.execute(
        "DELETE FROM scan_events WHERE level IN ('error','warning') AND LOWER(message) LIKE ?",
        (f'%{kw.lower()}%',)
    ).rowcount
    total_deleted += n

conn.commit()

remaining = conn.execute(
    "SELECT COUNT(*) FROM scan_events WHERE level IN ('error','warning')"
).fetchone()[0]

print(f"Before: {total_before}  Deleted: {total_deleted}  Remaining: {remaining}")

if remaining > 0:
    print("\nRemaining events (up to 20):")
    for row in conn.execute(
        "SELECT id, level, substr(message,1,100) FROM scan_events "
        "WHERE level IN ('error','warning') ORDER BY id DESC LIMIT 20"
    ).fetchall():
        print(f"  [{row[1]}] {row[2]}")

conn.close()
print("Done.")
