"""Database session management.

Single source of truth for:
  - engine creation
  - SessionLocal factory
  - `get_db` FastAPI dependency
  - `apply_migrations()` — runs the versioned migration framework at startup
"""
from __future__ import annotations

import logging
import os
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

logger = logging.getLogger(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./technieum.db")

# Build connect_args for SQLite — busy_timeout prevents "database is locked"
# errors when the scan worker holds the write lock while the API server tries
# to read.  30 000 ms (30 s) matches SQLAlchemy's pool_timeout default.
_sqlite_connect_args: dict = {}
if "sqlite" in DATABASE_URL:
    _sqlite_connect_args = {
        "check_same_thread": False,
        "timeout": 30,  # seconds SQLite will wait for a write-lock to release
    }

engine = create_engine(
    DATABASE_URL,
    connect_args=_sqlite_connect_args if "sqlite" in DATABASE_URL else {},
)

# Enable WAL journal mode for SQLite — allows concurrent readers while a
# writer holds the lock, preventing API requests from timing out during scans.
if "sqlite" in DATABASE_URL:
    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _conn_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")  # safe + faster than FULL
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def apply_migrations() -> None:
    """Apply all pending versioned migrations and create missing tables.

    Safe to call on every startup — each migration is idempotent.
    """
    from app.db.base import Base
    from app.db.migrations.versions import register  # noqa: F401 — side-effect: registers migrations
    from app.db.migrations.runner import run_migrations

    # Fix known schema issues before create_all
    _fix_legacy_scan_progress(engine)

    # Ensure all tables defined by the ORM exist (creates new tables only,
    # never drops existing ones).
    Base.metadata.create_all(bind=engine)

    # Apply any pending versioned migrations.
    run_migrations(engine)

    # Remove orphaned child rows whose scan_run no longer exists.
    # These can accumulate when the old broken delete code rolled back child
    # deletes but still committed the scan_run row deletion, leaving
    # scan_progress / scan_jobs rows that prevent new scans from being created
    # (UNIQUE constraint on scan_progress.scan_run_id).
    _purge_orphaned_child_rows(engine)


def _fix_legacy_scan_progress(eng) -> None:
    """Detect and fix the old scan_progress table that has wrong columns."""
    import sqlite3
    try:
        with eng.connect() as conn:
            result = conn.execute(text("PRAGMA table_info(scan_progress)"))
            cols = {row[1] for row in result.fetchall()}
            # Old schema had 'target', 'phase1_done' etc.; new ORM needs 'scan_run_id'
            if cols and "scan_run_id" not in cols:
                conn.execute(text("ALTER TABLE scan_progress RENAME TO _old_scan_progress_backup"))
                conn.commit()
    except Exception:
        pass  # table might not exist yet — that's fine


def _purge_orphaned_child_rows(eng) -> None:
    """Delete child-table rows whose scan_run_id no longer references a scan.

    This one-time cleanup repairs DBs where the old broken delete logic had
    rolled back child-table deletions but still committed the scan_run row
    removal, leaving orphan rows that cause UNIQUE constraint failures when
    SQLite reuses auto-increment IDs for new scans.
    """
    _orphan_tables = [
        "scan_events",
        "scan_jobs",
        "scan_progress",
        "baseline_snapshots",
        "malware_indicators",
        "data_leaks",
        "compliance_reports",
        "asset_snapshots",
        "risk_scores",
        "threat_intel_data",
        "isp_locations",
        "dns_records",
        "domain_technologies",
        "vulnerability_metadata",
        "vulnerabilities",
        "http_headers",
        "port_scans",
        "subdomains",
        "scan_runner_metadata",
        "saved_reports",
    ]
    try:
        with eng.connect() as conn:
            # compliance_evidence and compliance_findings reference compliance_reports
            for sub_table, sub_col, parent_table in [
                ("compliance_evidence", "compliance_report_id", "compliance_reports"),
                ("compliance_findings", "report_id",            "compliance_reports"),
            ]:
                try:
                    conn.execute(text(
                        f"DELETE FROM {sub_table}"
                        f" WHERE {sub_col} IN"
                        f" (SELECT {sub_table}.{sub_col} FROM {sub_table}"
                        f"  LEFT JOIN scan_runs ON scan_runs.id ="
                        f"  (SELECT scan_run_id FROM {parent_table}"
                        f"   WHERE {parent_table}.id = {sub_table}.{sub_col} LIMIT 1)"
                        f"  WHERE scan_runs.id IS NULL)"
                    ))
                except Exception:
                    pass  # table may not exist

            for table in _orphan_tables:
                try:
                    conn.execute(text(
                        f"DELETE FROM {table}"
                        f" WHERE scan_run_id NOT IN (SELECT id FROM scan_runs)"
                    ))
                except Exception:
                    pass  # table may not exist or no scan_run_id column
            conn.commit()
            logger.debug("Orphaned child rows purged successfully.")
    except Exception as exc:
        logger.warning("Could not purge orphaned child rows: %s", exc)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yield a DB session and close it on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Database:
    """Convenience wrapper for non-FastAPI contexts (middleware, CLI)."""

    def __init__(self) -> None:
        self.session: Session | None = None

    def connect(self) -> None:
        self.session = SessionLocal()

    def close(self) -> None:
        if self.session:
            self.session.close()
