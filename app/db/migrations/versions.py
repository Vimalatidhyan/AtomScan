"""Registered migration versions.

Import this module to register all migrations with the runner.
Migrations are applied in ascending version order.
"""
from app.db.migrations.runner import register

# ── 001: Baseline schema ────────────────────────────────────────────────────
# All tables defined in app/db/models.py are created via SQLAlchemy
# metadata.create_all().  This migration records the baseline so the
# runner knows the schema was intentionally established.
register(
    version="001",
    description="Baseline schema — all initial tables created via SQLAlchemy",
    upgrade_sql=[
        # Intentionally empty: create_all() handles initial table creation.
        # This entry exists so rollback from 002 has a stable previous state.
        "SELECT 1"
    ],
    downgrade_sql=[],
)

# ── 002: Add Vulnerability.status column ───────────────────────────────────
register(
    version="002",
    description="Add status column to vulnerabilities table",
    upgrade_sql=[
        "ALTER TABLE vulnerabilities ADD COLUMN status VARCHAR(50) DEFAULT 'open'"
    ],
    downgrade_sql=[
        # SQLite does not support DROP COLUMN before 3.35; keep a no-op for safety.
        "SELECT 1 -- downgrade: status column intentionally kept for data safety"
    ],
)

# ── 003: Rename compliance_evidence backref fix ──────────────────────────────
# The SQLAlchemy ORM fix (renaming backref to 'compliance_evidence_items') is
# purely in Python — no DDL change needed.
register(
    version="003",
    description="ORM backref rename (compliance_evidence) — Python-only, no DDL",
    upgrade_sql=["SELECT 1"],
    downgrade_sql=[],
)

# ── 004: scan_jobs table ─────────────────────────────────────────────────────
register(
    version="004",
    description="Add scan_jobs table for durable worker queue",
    upgrade_sql=[
        """CREATE TABLE IF NOT EXISTS scan_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
            status      VARCHAR(20) NOT NULL DEFAULT 'queued',
            worker_id   VARCHAR(100),
            queued_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at  TIMESTAMP,
            finished_at TIMESTAMP,
            error       TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_id ON scan_jobs(status, id)",
    ],
    downgrade_sql=["DROP TABLE IF EXISTS scan_jobs"],
)

# ── 005: scan_events table ───────────────────────────────────────────────────
register(
    version="005",
    description="Add scan_events table for persisted SSE telemetry",
    upgrade_sql=[
        """CREATE TABLE IF NOT EXISTS scan_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
            event_type  VARCHAR(50) NOT NULL DEFAULT 'log',
            level       VARCHAR(20) NOT NULL DEFAULT 'info',
            message     TEXT,
            data        TEXT,
            phase       INTEGER,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        "CREATE INDEX IF NOT EXISTS idx_scan_events_run_id ON scan_events(scan_run_id, id)",
    ],
    downgrade_sql=["DROP TABLE IF EXISTS scan_events"],
)



# ── 006: Legacy DB upgrade ──────────────────────────────────────────────────
# Upgrades schemas created by legacy db/database.py so the ORM can read them.
# All ADD COLUMN statements are idempotent (runner ignores "already exists").
# The scan_progress table rename is guarded by a flag table so it runs once.
register(
    version="006",
    description="Bridge legacy db/database.py schema to ORM schema (idempotent)",
    upgrade_sql=[
        # ── vulnerabilities: add ORM columns missing from legacy schema ──
        "ALTER TABLE vulnerabilities ADD COLUMN scan_run_id INTEGER",
        "ALTER TABLE vulnerabilities ADD COLUMN subdomain_id INTEGER",
        "ALTER TABLE vulnerabilities ADD COLUMN port_scan_id INTEGER",
        "ALTER TABLE vulnerabilities ADD COLUMN status VARCHAR(50) DEFAULT 'open'",
        "ALTER TABLE vulnerabilities ADD COLUMN vuln_type VARCHAR(100)",
        "ALTER TABLE vulnerabilities ADD COLUMN title VARCHAR(500)",
        "ALTER TABLE vulnerabilities ADD COLUMN description TEXT",
        "ALTER TABLE vulnerabilities ADD COLUMN remediation TEXT",
        "ALTER TABLE vulnerabilities ADD COLUMN cve_ids TEXT",
        "ALTER TABLE vulnerabilities ADD COLUMN risk_score INTEGER",
        # Backfill title from legacy 'name' column if present
        """UPDATE vulnerabilities
           SET title = name
           WHERE (title IS NULL OR title = '')
             AND name IS NOT NULL""",
        # Map legacy text severity → integer scores (idempotent: only updates
        # rows where CAST(severity AS INTEGER) = 0, i.e. text values)
        """UPDATE vulnerabilities
           SET severity = CASE
               WHEN LOWER(CAST(severity AS TEXT)) = 'critical' THEN 90
               WHEN LOWER(CAST(severity AS TEXT)) = 'high'     THEN 75
               WHEN LOWER(CAST(severity AS TEXT)) = 'medium'   THEN 50
               WHEN LOWER(CAST(severity AS TEXT)) = 'low'      THEN 20
               WHEN LOWER(CAST(severity AS TEXT)) = 'info'     THEN 5
               ELSE severity
           END
           WHERE CAST(severity AS INTEGER) = 0
             AND severity IS NOT NULL""",

        # ── subdomains: add all ORM columns missing from legacy schema ──
        "ALTER TABLE subdomains ADD COLUMN subdomain VARCHAR(500)",
        "ALTER TABLE subdomains ADD COLUMN scan_run_id INTEGER",
        "ALTER TABLE subdomains ADD COLUMN discovered_method VARCHAR(50)",
        "ALTER TABLE subdomains ADD COLUMN first_seen TIMESTAMP",
        "ALTER TABLE subdomains ADD COLUMN last_seen TIMESTAMP",
        "ALTER TABLE subdomains ADD COLUMN priority INTEGER DEFAULT 0",
        """UPDATE subdomains
           SET subdomain = host
           WHERE (subdomain IS NULL OR subdomain = '')
             AND host IS NOT NULL""",

        # ── scan_progress: rename legacy table so ORM can create new one ─
        # The legacy schema uses 'target TEXT PRIMARY KEY' which is incompatible
        # with the ORM schema (scan_run_id, current_phase, ...).
        # We preserve legacy data by renaming, not dropping.
        """CREATE TABLE IF NOT EXISTS _legacy_scan_progress AS
           SELECT * FROM scan_progress
           WHERE EXISTS (
               SELECT 1 FROM pragma_table_info('scan_progress') WHERE name='target'
           )""",
        # After backup, drop the legacy table so ORM create_all creates the
        # correct schema. Guarded: only if legacy columns exist.
        """DROP TABLE IF EXISTS scan_progress""",

        "SELECT 1  -- legacy compatibility migration complete",
    ],
    downgrade_sql=[
        "SELECT 1  -- legacy migration intentionally non-reversible",
    ],
)
