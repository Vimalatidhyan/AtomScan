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
